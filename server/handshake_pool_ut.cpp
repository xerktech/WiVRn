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

// Tests for the concurrent handshake pool and the PIN throttle, over loopback TCP.
// Built standalone in CI (.github/workflows/Sockets-UT.yml): the server target needs Monado.
#include "handshake_pool.h"

#include <arpa/inet.h>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace wivrn;
using namespace std::chrono_literals;

static int failures = 0;
#define CHECK(c)                                                            \
	do                                                                  \
	{                                                                   \
		if (!(c))                                                   \
		{                                                           \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
			++failures;                                         \
		}                                                           \
		else                                                        \
			printf("ok   %s\n", #c);                            \
	} while (0)

// Server side of a loopback connection whose client comes from source (127.0.0.x)
static TCP connect_from(TCPListener & listener, const char * source, int & client)
{
	sockaddr_in6 a{};
	socklen_t len = sizeof(a);
	getsockname(listener.get_fd(), (sockaddr *)&a, &len);

	client = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in src{};
	src.sin_family = AF_INET;
	inet_pton(AF_INET, source, &src.sin_addr);
	bind(client, (sockaddr *)&src, sizeof(src));

	sockaddr_in dst{};
	dst.sin_family = AF_INET;
	dst.sin_port = a.sin6_port;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	connect(client, (sockaddr *)&dst, sizeof(dst));

	return listener.accept().first;
}

template <typename T>
static std::optional<T> take_within(handshake_pool<T> & pool, std::chrono::milliseconds timeout)
{
	auto end = std::chrono::steady_clock::now() + timeout;
	while (std::chrono::steady_clock::now() < end)
	{
		if (auto r = pool.take())
			return r;
		std::this_thread::sleep_for(5ms);
	}
	return std::nullopt;
}

using pool_t = handshake_pool<int>;

// Handshake that waits for its peer until cancelled, like a peer that never sends its PIN
static int stall(std::stop_token stop, const pool_t::wait_report & waiting, std::atomic<int> & cancelled)
{
	waiting(true);
	while (not stop.stop_requested())
		std::this_thread::sleep_for(5ms);
	++cancelled;
	throw std::runtime_error("Connection cancelled");
}

static std::string addr(int a, int b)
{
	return "127.0." + std::to_string(a) + "." + std::to_string(b);
}

static void test_handshake_pool()
{
	TCPListener listener(0);
	std::atomic<int> cancelled = 0;
	std::vector<int> clients;
	auto conn = [&](const std::string & source) {
		int c;
		TCP t = connect_from(listener, source.c_str(), c);
		clients.push_back(c);
		return t;
	};
	auto staller = [&](std::stop_token s, TCP &&, const pool_t::wait_report & w) { return stall(s, w, cancelled); };
	auto value = [](int v) { return [v](std::stop_token, TCP &&, const pool_t::wait_report &) { return v; }; };
	auto junk = [](std::stop_token, TCP &&, const pool_t::wait_report &) -> int { throw std::runtime_error("junk first record"); };

	{
		pool_t pool;

		// A stalled handshake does not stop another peer from getting through
		pool.start(conn(addr(0, 2)), staller);
		pool.start(conn(addr(0, 3)), value(7));
		CHECK(pool.size() == 2);
		CHECK(take_within(pool, 2s) == 7);
		CHECK(pool.size() == 1);

		// A failed handshake is dropped, the stalled one is untouched
		pool.start(conn(addr(0, 4)), junk);
		CHECK(not take_within(pool, 200ms));
		CHECK(pool.size() == 1);
		CHECK(cancelled == 0);

		// A new connection from the same address replaces that peer's attempt
		pool.start(conn(addr(0, 2)), value(8));
		CHECK(pool.size() == 1);
		CHECK(take_within(pool, 2s) == 8);
		std::this_thread::sleep_for(100ms);
		pool.take(); // Reaps the cancelled thread
		CHECK(cancelled == 1);

		// Destroying the pool cancels what is left
		pool.start(conn(addr(0, 5)), staller);
	}
	CHECK(cancelled == 2);

	{
		// One address cannot fill the pool
		pool_t pool;
		for (size_t i = 0; i < pool_t::max_attempts + 2; ++i)
			pool.start(conn(addr(0, 6)), staller);
		CHECK(pool.size() == 1);
	}

	{
		// Stalled peers on many addresses: a new peer takes the place of the one that has waited
		// longest, once it has waited stall_after
		pool_t pool;
		std::atomic<int> first_cancelled = 0;
		pool.start(conn(addr(1, 1)), [&](std::stop_token s, TCP && t, const pool_t::wait_report & w) {
			try
			{
				return stall(s, w, cancelled);
			}
			catch (...)
			{
				first_cancelled = 1;
				throw;
			}
		});
		std::this_thread::sleep_for(20ms);
		for (size_t i = 1; i < pool_t::max_attempts; ++i)
			pool.start(conn(addr(1, i + 1)), staller);
		std::this_thread::sleep_for(50ms);
		CHECK(pool.size() == pool_t::max_attempts);

		// Not stalled long enough yet: the newcomer is dropped, nothing is cancelled
		int before = cancelled;
		std::atomic<bool> ran = false;
		pool.start(conn(addr(2, 1)), [&](std::stop_token, TCP &&, const pool_t::wait_report &) { ran = true; return 1; }, pool_t::clock::now() - pool_t::stall_after);
		CHECK(pool.size() == pool_t::max_attempts);
		std::this_thread::sleep_for(50ms);
		CHECK(not ran);
		CHECK(cancelled == before);

		pool.start(conn(addr(2, 2)), value(9), pool_t::clock::now() + pool_t::stall_after);
		CHECK(take_within(pool, 2s) == 9);
		std::this_thread::sleep_for(100ms);
		pool.take(); // Reaps the evicted thread
		CHECK(cancelled == before + 1);
		CHECK(first_cancelled == 1); // The longest waiter went

		// clear() returns with every thread stopped
		pool.clear();
		CHECK(cancelled == before + int(pool_t::max_attempts));
		CHECK(pool.size() == 0);
	}

	{
		// A burst of new connections cannot cancel a headset partway through its handshake: it is
		// not waiting (or only briefly), and an authenticated one waiting to be taken is kept
		pool_t pool;
		std::atomic<bool> release = false;
		std::atomic<bool> busy_cancelled = false;
		pool.start(conn(addr(3, 1)), [&](std::stop_token s, TCP &&, const pool_t::wait_report &) -> int {
			while (not release and not s.stop_requested())
				std::this_thread::sleep_for(5ms);
			if (s.stop_requested())
			{
				busy_cancelled = true;
				throw std::runtime_error("cancelled");
			}
			return 3;
		});
		pool.start(conn(addr(3, 2)), value(4)); // Authenticated, not taken
		std::this_thread::sleep_for(50ms);
		for (size_t i = 2; i < pool_t::max_attempts; ++i)
			pool.start(conn(addr(4, i)), junk); // Junk fails by itself, never waits
		auto later = pool_t::clock::now() + 10 * pool_t::stall_after;
		for (int i = 0; i < 32; ++i)
			pool.start(conn(addr(5, i + 1)), junk, later);
		std::this_thread::sleep_for(100ms);
		CHECK(not busy_cancelled);
		CHECK(pool.take() == 4);
		release = true;
		CHECK(take_within(pool, 2s) == 3);
		CHECK(pool.size() == 0);
	}

	for (int c: clients)
		close(c);
}

static void test_pin_throttle()
{
	pin_throttle t;
	auto now = pin_throttle::clock::time_point{} + 1h;

	// One check at a time
	CHECK(t.try_begin(now));
	CHECK(not t.try_begin(now));

	// A wrong PIN blocks the next check for a doubling delay
	CHECK(t.end(false, now) == 20ms);
	CHECK(not t.try_begin(now + 19ms));
	CHECK(t.try_begin(now + 20ms));
	now += 20ms;
	CHECK(t.end(false, now) == 40ms);

	// Capped
	for (int i = 0; i < 30; ++i)
	{
		now += pin_throttle::max_delay;
		CHECK(t.try_begin(now));
		t.end(false, now);
	}
	now += pin_throttle::max_delay;
	CHECK(t.try_begin(now));
	CHECK(t.end(false, now) == pin_throttle::max_delay);

	// A correct PIN resets it
	now += pin_throttle::max_delay;
	CHECK(t.try_begin(now));
	CHECK(t.end(true, now) == 0ms);
	CHECK(t.try_begin(now));
	CHECK(t.end(false, now) == 20ms);
}

int main()
{
	test_handshake_pool();
	test_pin_throttle();

	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("all passed\n");
	return 0;
}
