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
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
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
// Only one PIN check runs at a time, and each wrong (or abandoned) one doubles the wait before the
// next is allowed, up to max_delay. It throttles PIN guessing, not connections: a headset that is
// already paired never goes through a PIN check, so a peer guessing PINs cannot delay it.
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

	// Ends the check started by try_begin, returns the wait before the next one
	std::chrono::milliseconds end(bool correct, clock::time_point now = clock::now())
	{
		std::lock_guard lock(mutex);
		busy = false;
		if (correct)
		{
			delay = initial_delay;
			next_allowed = now;
			return std::chrono::milliseconds(0);
		}
		delay = std::min(2 * delay, max_delay);
		next_allowed = now + delay;
		return delay;
	}
};

// Runs the authenticating part of several handshakes at once, each on its own thread, so a peer
// that stalls (waiting for a PIN, sending a junk first record) cannot keep the headset out.
// A peer gets at most one attempt: a new connection from the same address cancels its previous
// one, so a headset that reconnects replaces its own stale attempt. When the pool is full, the
// oldest unfinished attempt is cancelled to make room, so peers using many addresses cannot keep a
// new one out either: a headset authenticates in well under a second, a stalled peer never does.
// Tests: test_handshake_pool in server/handshake_pool_ut.cpp.
template <typename Result>
class handshake_pool
{
public:
	using handshake = std::function<Result(std::stop_token, TCP &&)>;
	static constexpr size_t max_attempts = handshake_gate::max_pending;

private:
	struct outcome
	{
		std::atomic<bool> done = false;
		std::optional<Result> result; // Written by the thread before done is set
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

	void reap_stale()
	{
		// A cancelled thread notices within one poll interval; only finished ones are joined (on
		// erase), so this never blocks the caller
		std::erase_if(stale, [](const attempt & a) { return a.state->done.load(std::memory_order_acquire); });
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

	// Starts a handshake on tcp, cancelling any attempt still running for the same peer address,
	// and the oldest unfinished one if the pool is full
	void start(TCP && tcp, handshake fn)
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

		if (attempts.size() >= max_attempts)
		{
			auto oldest = std::ranges::find_if(attempts, [](const attempt & a) { return not a.state->done.load(std::memory_order_acquire); });
			if (oldest == attempts.end())
				oldest = attempts.begin(); // All finished, none taken yet: drop the oldest result
			oldest->thread.request_stop();
			stale.splice(stale.end(), attempts, oldest);
		}

		auto state = std::make_shared<outcome>();
		std::jthread thread([state, fn = std::move(fn)](std::stop_token stop, TCP && tcp) {
			try
			{
				state->result.emplace(fn(stop, std::move(tcp)));
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
		reap_stale();

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
