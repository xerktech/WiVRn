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

// Tests for wivrn::authenticate, the server side of the crypto handshake, against a headset
// driven by hand over loopback TCP.
// Built standalone in CI (.github/workflows/Sockets-UT.yml): the server target needs Monado.
#include "authenticate.h"
#include "known_keys.h"
#include "protocol_version.h"
#include "smp.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace wivrn;
using namespace std::chrono_literals;
using clock_type = std::chrono::steady_clock;

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

// known_keys.h normally reads the configuration directory: no headset is paired, and the server
// identity key is generated once for the whole run
static const std::string identity_pem = crypto::key::generate_x448_keypair().private_key();

crypto::key wivrn::server_identity_key()
{
	return crypto::key::from_private_key(identity_pem);
}

std::vector<headset_key> wivrn::known_keys()
{
	return {};
}

using headset_socket = typed_socket<TCP, to_headset::packets, from_headset::packets>;
using server_socket = typed_socket<TCP, from_headset::packets, to_headset::packets>;

// Next packet on s, or throws after timeout
template <typename Socket>
static auto receive(Socket & s, std::chrono::milliseconds timeout = 10s)
{
	auto end = clock_type::now() + timeout;
	while (true)
	{
		if (auto packet = s.receive_pending())
			return std::move(*packet);

		pollfd fds{.fd = s.get_fd(), .events = POLLIN};
		if (::poll(&fds, 1, 50) < 0)
			throw std::system_error(errno, std::system_category());
		if (fds.revents & POLLIN)
		{
			if (auto packet = s.receive())
				return std::move(*packet);
		}
		if (clock_type::now() > end)
			throw std::runtime_error("timeout");
	}
}

// One authenticate() call on a background thread, with the headset end of its socket
struct handshake
{
	struct event
	{
		bool waiting;
		clock_type::time_point time;
	};

	headset_socket headset;
	std::mutex mutex;
	std::vector<event> events; // Calls to the waiting callback
	std::optional<authenticated_peer> peer;
	std::string error;
	bool incorrect_pin = false;
	clock_type::time_point ended;
	std::thread thread;

	handshake(encryption_state state, const std::string & pin)
	{
		TCPListener listener(0);
		sockaddr_in6 a{};
		socklen_t len = sizeof(a);
		getsockname(listener.get_fd(), (sockaddr *)&a, &len);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = a.sin6_port;
		dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		headset = headset_socket(dst);

		thread = std::thread([this, state, pin, tcp = listener.accept().first]() mutable {
			try
			{
				auto result = authenticate(std::stop_token{}, state, pin, std::move(tcp), [this](bool w) {
					std::lock_guard lock(mutex);
					events.push_back({w, clock_type::now()});
				});
				std::lock_guard lock(mutex);
				peer.emplace(std::move(result));
			}
			catch (wivrn::incorrect_pin &)
			{
				std::lock_guard lock(mutex);
				incorrect_pin = true;
			}
			catch (std::exception & e)
			{
				std::lock_guard lock(mutex);
				error = e.what();
			}
			ended = clock_type::now();
		});
	}

	~handshake()
	{
		join();
	}

	void join()
	{
		if (thread.joinable())
			thread.join();
	}
};

// Headset side of a pairing handshake (client/wivrn_client.cpp), up to the server's verdict.
// Returns whether the PIN matched; t3/t4 are when pin_check_3 was sent and pin_check_4 arrived.
struct pairing_result
{
	bool pin_match = false;
	clock_type::time_point t3, t4;
};

static pairing_result pair(handshake & h, crypto::key & headset_key, const std::string & pin)
{
	h.headset.send(from_headset::crypto_handshake{
	        .protocol_version = protocol_version,
	        .public_key = headset_key.public_key(),
	        .name = "test headset",
	});

	auto reply = std::get<to_headset::crypto_handshake>(receive(h.headset));
	if (reply.state != to_headset::crypto_handshake::crypto_state::pin_needed)
		throw std::runtime_error("expected pin_needed");
	auto server_identity = crypto::key::from_public_key(reply.identity_key);
	auto server_ephemeral = crypto::key::from_public_key(reply.public_key);

	pairing_result result;
	crypto::smp pin_check;
	h.headset.send(from_headset::pin_check_1{pin_check.step1(pin_check_secret(pin, server_identity, headset_key))});
	auto msg2 = std::get<to_headset::pin_check_2>(receive(h.headset)).message;
	auto msg3 = pin_check.step3(msg2);
	result.t3 = clock_type::now();
	h.headset.send(from_headset::pin_check_3{msg3});
	auto msg4 = std::get<to_headset::pin_check_4>(receive(h.headset)).message;
	result.t4 = clock_type::now();
	result.pin_match = pin_check.step5(msg4);

	if (result.pin_match)
	{
		auto s = secrets::headset(headset_key, server_ephemeral, server_identity, pin);
		h.headset.set_aes_key_and_ivs(s.control_key, s.control_iv_to_headset, s.control_iv_from_headset);
		h.headset.send(from_headset::crypto_handshake{});
	}
	return result;
}

// The 64 KiB cap on records before authentication: a length prefix alone must not make the server
// wait for (and allocate) a large record
static void test_oversized_first_record()
{
	handshake h(encryption_state::pairing, "123456");

	uint32_t size = 1024 * 1024; // Under TCP::default_max_payload, over the handshake cap
	auto start = clock_type::now();
	CHECK(::send(h.headset.get_fd(), &size, sizeof(size), MSG_NOSIGNAL) == sizeof(size));
	h.join();

	CHECK(not h.peer);
	CHECK(h.error.starts_with("Invalid packet: size"));
	CHECK(h.ended - start < 2s);
}

// After a successful pairing the cap is lifted: the session's own packets can be larger
static void test_cap_restored_after_pairing()
{
	handshake h(encryption_state::pairing, "123456");
	auto headset_key = crypto::key::generate_x448_keypair();

	auto result = pair(h, headset_key, "123456");
	h.join();

	CHECK(result.pin_match);
	CHECK(h.error.empty());
	CHECK(h.peer and h.peer->add_key);
	if (not h.peer)
		return;

	server_socket control(std::move(h.peer->control));
	from_headset::crypto_handshake big{.name = std::string(256 * 1024, 'x')};
	h.headset.send(std::move(big));
	try
	{
		auto packet = receive(control, 2s);
		auto * received = std::get_if<from_headset::crypto_handshake>(&packet);
		CHECK(received and received->name.size() == 256 * 1024);
	}
	catch (std::exception & e)
	{
		printf("receive after hand-off: %s\n", e.what());
		CHECK(!"large record received after hand-off");
	}
}

// A PIN check that has to wait for the throttle (after wrong PINs) waits rather than refusing,
// and reports that wait so the handshake pool may evict it
static void test_throttle_wait_reported()
{
	// Each wrong PIN doubles the wait before the next check: after 8 it is 2.56s, under the 8s
	// the server waits for the throttle, and long enough to tell from the waits on the peer even
	// when the test runs slowly.
	for (int i = 0; i < 8; ++i)
	{
		handshake h(encryption_state::pairing, "123456");
		auto headset_key = crypto::key::generate_x448_keypair();
		auto result = pair(h, headset_key, "654321");
		h.join();
		CHECK(not result.pin_match);
		CHECK(h.incorrect_pin);
	}

	handshake h(encryption_state::pairing, "123456");
	auto headset_key = crypto::key::generate_x448_keypair();
	auto result = pair(h, headset_key, "123456");
	h.join();

	CHECK(result.pin_match);
	CHECK(h.error.empty());
	CHECK(h.peer.has_value());
	CHECK(result.t4 - result.t3 >= 1s);
	CHECK(result.t4 - result.t3 < 8s);

	// The throttle wait: waiting(true) then waiting(false) for over a second, before pin_check_4.
	// The waits on the peer around it are short, the headset answers at once.
	bool reported = false;
	for (size_t i = 0; i + 1 < h.events.size(); ++i)
	{
		auto & a = h.events[i];
		auto & b = h.events[i + 1];
		if (a.waiting and not b.waiting and b.time <= result.t4 and b.time - a.time >= 1s)
			reported = true;
	}
	CHECK(reported);
	if (not reported)
		for (auto & e: h.events)
			printf("  waiting(%d) at %+lldms from pin_check_3\n", e.waiting, (long long)std::chrono::duration_cast<std::chrono::milliseconds>(e.time - result.t3).count());

	// A correct PIN resets the throttle: the next pairing is not delayed
	handshake next(encryption_state::pairing, "123456");
	auto next_key = crypto::key::generate_x448_keypair();
	auto next_result = pair(next, next_key, "123456");
	next.join();
	CHECK(next_result.pin_match);
	CHECK(next_result.t4 - next_result.t3 < 500ms);
}

int main()
{
	// The headset side throws if the server drops or refuses it
	for (auto test: {test_oversized_first_record, test_cap_restored_after_pairing, test_throttle_wait_reported})
	{
		try
		{
			test();
		}
		catch (std::exception & e)
		{
			printf("FAIL exception: %s\n", e.what());
			++failures;
		}
	}

	printf("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
