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
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

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

// Handshake that waits until cancelled, like a peer that never sends its PIN
static int stall(std::stop_token stop, TCP &&, std::atomic<int> & cancelled)
{
	while (not stop.stop_requested())
		std::this_thread::sleep_for(5ms);
	++cancelled;
	throw std::runtime_error("Connection cancelled");
}

static void test_handshake_pool()
{
	TCPListener listener(0);
	std::atomic<int> cancelled = 0;
	int c1, c2, c3, c4, c5;

	{
		handshake_pool<int> pool;

		// A stalled handshake does not stop another peer from getting through
		pool.start(connect_from(listener, "127.0.0.2", c1), [&](std::stop_token s, TCP && t) { return stall(s, std::move(t), cancelled); });
		pool.start(connect_from(listener, "127.0.0.3", c2), [](std::stop_token, TCP &&) { return 7; });
		CHECK(pool.size() == 2);
		auto r = take_within(pool, 2s);
		CHECK(r == 7);
		CHECK(pool.size() == 1);
		CHECK(cancelled == 0);

		// A failed handshake is dropped, the stalled one is untouched
		pool.start(connect_from(listener, "127.0.0.4", c3), [](std::stop_token, TCP &&) -> int { throw std::runtime_error("junk first record"); });
		CHECK(not take_within(pool, 200ms));
		CHECK(pool.size() == 1);
		CHECK(cancelled == 0);

		// A new connection from the same address replaces that peer's attempt
		pool.start(connect_from(listener, "127.0.0.2", c4), [](std::stop_token, TCP &&) { return 8; });
		CHECK(pool.size() == 1);
		CHECK(take_within(pool, 2s) == 8);
		std::this_thread::sleep_for(100ms);
		pool.take(); // Reaps the cancelled thread
		CHECK(cancelled == 1);

		// Destroying the pool cancels what is left
		pool.start(connect_from(listener, "127.0.0.5", c5), [&](std::stop_token s, TCP && t) { return stall(s, std::move(t), cancelled); });
	}
	CHECK(cancelled == 2);

	{
		// One address cannot fill the pool
		handshake_pool<int> pool;
		std::vector<int> clients(handshake_pool<int>::max_attempts + 2);
		for (int & c: clients)
			pool.start(connect_from(listener, "127.0.0.6", c), [&](std::stop_token s, TCP && t) { return stall(s, std::move(t), cancelled); });
		CHECK(pool.size() == 1);
		for (int c: clients)
			close(c);
	}

	{
		// Stalled peers on many addresses cannot keep a new one out for long: once older than
		// min_age, the oldest one makes room. Before that, fresh connections cannot evict anything.
		using pool_t = handshake_pool<int>;
		pool_t pool;
		auto t0 = pool_t::clock::now();
		std::vector<int> clients(pool_t::max_attempts);
		for (size_t i = 0; i < clients.size(); ++i)
		{
			std::string addr = "127.0.1." + std::to_string(i + 1);
			pool.start(connect_from(listener, addr.c_str(), clients[i]), [&](std::stop_token s, TCP && t) { return stall(s, std::move(t), cancelled); }, t0);
		}
		CHECK(pool.size() == pool_t::max_attempts);
		CHECK(not pool.has_room(t0 + pool_t::min_age - 1ms));

		// A burst arriving while every attempt is young is dropped, nothing is cancelled
		int before = cancelled;
		int junk;
		std::atomic<bool> junk_ran = false;
		pool.start(connect_from(listener, "127.0.2.2", junk), [&](std::stop_token, TCP &&) -> int { junk_ran = true; throw std::runtime_error("junk"); }, t0 + 1s);
		CHECK(pool.size() == pool_t::max_attempts);
		std::this_thread::sleep_for(100ms);
		CHECK(not junk_ran);
		CHECK(cancelled == before);

		auto later = t0 + pool_t::min_age;
		CHECK(pool.has_room(later));
		int headset;
		pool.start(connect_from(listener, "127.0.2.1", headset), [](std::stop_token, TCP &&) { return 9; }, later);
		CHECK(pool.size() == pool_t::max_attempts);
		CHECK(take_within(pool, 2s) == 9);
		std::this_thread::sleep_for(100ms);
		pool.take(); // Reaps the evicted thread
		CHECK(cancelled == before + 1);

		// clear() returns with every thread stopped
		pool.clear();
		CHECK(cancelled == before + int(clients.size()));
		CHECK(pool.size() == 0);
		close(junk);
		close(headset);
		for (int c: clients)
			close(c);
	}

	{
		// A headset that has authenticated but is not taken yet is never the one evicted
		using pool_t = handshake_pool<int>;
		pool_t pool;
		auto t0 = pool_t::clock::now();
		int headset;
		pool.start(connect_from(listener, "127.0.3.1", headset), [](std::stop_token, TCP &&) { return 5; }, t0);
		std::this_thread::sleep_for(100ms); // Finished, not taken
		std::vector<int> clients(pool_t::max_attempts - 1);
		for (size_t i = 0; i < clients.size(); ++i)
		{
			std::string addr = "127.0.4." + std::to_string(i + 1);
			pool.start(connect_from(listener, addr.c_str(), clients[i]), [&](std::stop_token s, TCP && t) { return stall(s, std::move(t), cancelled); }, t0);
		}
		auto later = t0 + pool_t::min_age;
		int other;
		CHECK(pool.has_room(later));
		pool.start(connect_from(listener, "127.0.3.2", other), [&](std::stop_token s, TCP && t) { return stall(s, std::move(t), cancelled); }, later);
		CHECK(pool.take() == 5);

		// Failed attempts free their slot without evicting anyone
		pool.clear();
		for (size_t i = 0; i < clients.size(); ++i)
		{
			std::string addr = "127.0.5." + std::to_string(i + 1);
			close(clients[i]);
			pool.start(connect_from(listener, addr.c_str(), clients[i]), [](std::stop_token, TCP &&) -> int { throw std::runtime_error("junk"); }, later);
		}
		std::this_thread::sleep_for(100ms);
		CHECK(pool.has_room(later));
		CHECK(pool.size() == 0);
		close(headset);
		close(other);
		for (int c: clients)
			close(c);
	}

	for (int c: {c1, c2, c3, c4, c5})
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
