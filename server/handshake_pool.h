/*
 * WiVRn VR streaming
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "wivrn_sockets.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <stop_token>
#include <sys/socket.h>
#include <thread>

namespace wivrn
{
// Rate limit on PIN checks, shared by every connection.
// Only one PIN check runs at a time, and each wrong one doubles the wait before the next is
// allowed, up to max_delay. A check holds the throttle only while the server computes its answer,
// never while waiting on the peer, so a stalling peer cannot block pairing.
// It throttles PIN guessing, not connections: a headset that is already paired never goes through
// a PIN check, so a peer guessing PINs cannot delay it.
// Tests: test_pin_throttle in server/handshake_pool_ut.cpp.
class pin_throttle
{
public:
	using clock = std::chrono::steady_clock;
	static constexpr std::chrono::milliseconds initial_delay{10};
	// Caps the lockout a guessing peer can cause; at one guess per 5 minutes a 6-digit PIN still
	// takes years to brute-force.
	static constexpr std::chrono::milliseconds max_delay = std::chrono::minutes(5);

private:
	std::mutex mutex;
	std::condition_variable_any changed;
	bool busy = false;
	clock::time_point next_allowed{};
	std::chrono::milliseconds delay = initial_delay;

public:
	// False if another PIN check is running or the wait after a wrong PIN has not elapsed
	bool try_begin(clock::time_point now = clock::now())
	{
		std::lock_guard lock(mutex);
		if (busy or now < next_allowed)
			return false;
		busy = true;
		return true;
	}

	// Like try_begin, but waits up to max_wait for the running check to end or the wait after a
	// wrong PIN to elapse, so a headset that just mistyped its PIN is not refused outright.
	// False on timeout or stop.
	bool begin(std::stop_token stop, clock::duration max_wait)
	{
		auto deadline = clock::now() + max_wait;
		std::unique_lock lock(mutex);
		while (true)
		{
			auto now = clock::now();
			if (not busy and now >= next_allowed)
			{
				busy = true;
				return true;
			}
			if (now >= deadline or stop.stop_requested())
				return false;
			// end() notifies when busy clears; the wait after a wrong PIN only needs the timeout.
			// The stop_token overload only returns early once its predicate holds, hence not_busy.
			if (busy)
				changed.wait_until(lock, stop, deadline, [this] { return not busy; });
			else
				changed.wait_until(lock, stop, std::min(next_allowed, deadline), [] { return false; });
		}
	}

	// Ends the check started by try_begin or begin, returns the wait before the next one
	std::chrono::milliseconds end(bool correct, clock::time_point now = clock::now())
	{
		std::chrono::milliseconds result{0};
		{
			std::lock_guard lock(mutex);
			busy = false;
			if (correct)
			{
				delay = initial_delay;
				next_allowed = now;
			}
			else
			{
				delay = std::min(2 * delay, max_delay);
				next_allowed = now + delay;
				result = delay;
			}
		}
		changed.notify_all();
		return result;
	}
};

// Runs the authenticating part of several handshakes at once, each on its own thread, so a peer
// that stalls (waiting for a PIN, sending a junk first record) cannot keep the headset out.
// A peer gets at most one attempt: a new connection from the same address cancels its previous
// one, so a headset that reconnects replaces its own stale attempt.
// The handshake reports when it waits for the peer. When the pool is full, the attempt that has
// waited longest is cancelled to make room, provided it has waited at least stall_after:
// - a peer that stalls (never sends its PIN or its encrypted confirmation) waits indefinitely,
// - a headset answers within a round trip, so it is not cancelled by a burst of new connections,
// - a junk record fails by itself without waiting.
// If nothing has stalled that long, the new connection is dropped rather than left queued, so a
// flood does not build a backlog in front of the headset (which has to connect again).
// Tests: test_handshake_pool in server/handshake_pool_ut.cpp.
template <typename Result>
class handshake_pool
{
public:
	using clock = std::chrono::steady_clock;
	// Called with true when the handshake starts waiting for the peer, false when data arrived
	using wait_report = std::function<void(bool)>;
	using handshake = std::function<Result(std::stop_token, TCP &&, const wait_report &)>;
	static constexpr size_t max_attempts = handshake_gate::max_pending;
	static constexpr std::chrono::milliseconds stall_after{100};

private:
	struct outcome
	{
		std::atomic<bool> done = false;
		std::optional<Result> result; // Written by the thread before done is set
		static constexpr clock::rep not_waiting = std::numeric_limits<clock::rep>::max();
		std::atomic<clock::rep> waiting_since = not_waiting;
	};

	struct attempt
	{
		in6_addr peer;
		std::shared_ptr<outcome> state;
		std::jthread thread;
	};

	std::list<attempt> attempts; // Oldest first
	std::list<attempt> stale;    // Cancelled, joined once finished

	static bool same_address(const in6_addr & a, const in6_addr & b)
	{
		return std::memcmp(&a, &b, sizeof(a)) == 0;
	}

	static bool finished(const attempt & a)
	{
		return a.state->done.load(std::memory_order_acquire);
	}

	// Joins finished threads (on erase) and drops failed attempts; never blocks the caller.
	// A cancelled thread notices within one poll interval.
	void reap()
	{
		std::erase_if(stale, finished);
		std::erase_if(attempts, [](const attempt & a) { return finished(a) and not a.state->result; });
	}

	// The attempt to cancel to make room: the one waiting for its peer the longest, if that is at
	// least stall_after
	std::list<attempt>::iterator evictable(clock::time_point now)
	{
		auto best = attempts.end();
		clock::rep best_since = (now - stall_after).time_since_epoch().count();
		for (auto it = attempts.begin(); it != attempts.end(); ++it)
		{
			if (finished(*it))
				continue;
			clock::rep since = it->state->waiting_since.load(std::memory_order_relaxed);
			if (since <= best_since)
			{
				best = it;
				best_since = since;
			}
		}
		return best;
	}

public:
	handshake_pool() = default;
	handshake_pool(const handshake_pool &) = delete;
	handshake_pool & operator=(const handshake_pool &) = delete;
	~handshake_pool()
	{
		clear();
	}

	size_t size() const
	{
		return attempts.size();
	}

	// Starts a handshake on tcp, cancelling any attempt still running for the same peer address.
	// When the pool is full, cancels the longest stalled attempt, or drops tcp if none has stalled.
	void start(TCP && tcp, handshake fn, clock::time_point now = clock::now())
	{
		sockaddr_in6 addr{};
		socklen_t len = sizeof(addr);
		if (::getpeername(tcp.get_fd(), (sockaddr *)&addr, &len) < 0)
			return; // Already disconnected

		for (auto it = attempts.begin(); it != attempts.end();)
		{
			if (same_address(it->peer, addr.sin6_addr))
			{
				it->thread.request_stop();
				auto next = std::next(it);
				stale.splice(stale.end(), attempts, it);
				it = next;
			}
			else
				++it;
		}

		reap();
		if (attempts.size() >= max_attempts)
		{
			auto oldest = evictable(now);
			if (oldest == attempts.end())
				return; // Nothing has stalled: keep the attempts in progress, drop tcp
			oldest->thread.request_stop();
			stale.splice(stale.end(), attempts, oldest);
		}

		auto state = std::make_shared<outcome>();
		std::jthread thread([state, fn = std::move(fn)](std::stop_token stop, TCP && tcp) {
			try
			{
				wait_report waiting = [&state](bool w) {
					state->waiting_since.store(w ? clock::now().time_since_epoch().count() : outcome::not_waiting, std::memory_order_relaxed);
				};
				state->result.emplace(fn(stop, std::move(tcp), waiting));
			}
			catch (std::exception & e)
			{
				// Cancelled attempts are expected (another peer won, or it reconnected): not logged
				if (not stop.stop_requested())
					std::cerr << "Handshake failed: " << e.what() << std::endl;
			}
			catch (...)
			{
				if (not stop.stop_requested())
					std::cerr << "Handshake failed" << std::endl;
			}
			state->done.store(true, std::memory_order_release);
		},
		                    std::move(tcp));

		attempts.push_back({addr.sin6_addr, std::move(state), std::move(thread)});
	}

	// Collects finished attempts and returns the oldest one that succeeded, if any.
	// Other successful attempts stay queued for the next call.
	std::optional<Result> take()
	{
		std::erase_if(stale, finished);

		for (auto it = attempts.begin(); it != attempts.end();)
		{
			if (not it->state->done.load(std::memory_order_acquire))
			{
				++it;
				continue;
			}

			it->thread.join();
			std::optional<Result> result = std::move(it->state->result);
			it = attempts.erase(it);
			if (result)
				return result;
		}
		return std::nullopt;
	}

	// Cancels every attempt and waits for the threads to exit
	void clear()
	{
		for (auto & a: attempts)
			a.thread.request_stop();
		for (auto & a: stale)
			a.thread.request_stop();
		attempts.clear(); // jthread joins on destruction
		stale.clear();
	}
};
} // namespace wivrn
