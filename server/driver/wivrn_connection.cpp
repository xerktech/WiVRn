/*
 * WiVRn VR streaming
 * Copyright (C) 2022  Guillaume Meunier <guillaume.meunier@centraliens.net>
 * Copyright (C) 2022  Patrick Nicolas <patricknicolas@laposte.net>
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

#include "wivrn_connection.h"
#include "configuration.h"
#include "handshake_identity.h"
#include "handshake_pool.h"
#include "protocol_version.h"
#include "secrets.h"
#include "smp.h"
#include "wivrn_ipc.h"
#include "wivrn_packets.h"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <regex>
#include <sys/socket.h>
#include <variant>

using namespace std::chrono_literals;

// Ignored until connection is established
static void handle_event_from_main_loop(to_monado::stop) {}
static void handle_event_from_main_loop(to_monado::disconnect) {}
static void handle_event_from_main_loop(to_monado::set_bitrate) {}
static void handle_event_from_main_loop(wivrn::to_headset::stream_tab_change) {}

static std::string clean_key(std::string key)
{
	static const std::regex header{"^-+BEGIN .*-+$", std::regex_constants::multiline};
	static const std::regex footer{"^-+END .*-+$", std::regex_constants::multiline};
	static const std::regex whitespace{"[[:space:]]"};

	key = std::regex_replace(key, header, "");
	key = std::regex_replace(key, footer, "");
	key = std::regex_replace(key, whitespace, "");

	return key;
}

wivrn::incorrect_pin::incorrect_pin() :
        std::runtime_error("Incorrect PIN") {}

wivrn::wivrn_connection::wivrn_connection(std::stop_token stop_token, encryption_state state, std::string pin, authenticated_peer && peer) :
        stream(-1),
        pin(pin),
        state(state)
{
	init(stop_token, std::move(peer));
}

namespace
{
// Largest record accepted before the peer is authenticated: the PEM keys, the headset name and the
// SMP messages of the PIN check are a few KiB
constexpr size_t authenticate_max_payload = 64 * 1024;

// Only one PIN check at a time, with a growing wait after each wrong one, for the whole server
wivrn::pin_throttle pin_attempts;

// The identity key file is created on first use: serialize so concurrent handshakes cannot each
// create (and send) a different key
std::mutex identity_key_mutex;

class pin_attempt
{
	bool correct = false;

public:
	// The headset waits 10s for pin_check_2 (client/wivrn_client.cpp): wait for a free slot for
	// less than that rather than refusing, so a user who mistyped once just retries. The wait
	// counts as waiting for the peer, so the handshake pool can still cancel it to make room.
	pin_attempt(std::stop_token stop, const std::function<void(bool)> & waiting)
	{
		if (waiting)
			waiting(true);
		bool ok = pin_attempts.begin(stop, std::chrono::seconds(8));
		if (waiting)
			waiting(false);
		if (not ok)
			throw std::runtime_error("PIN check refused: another check is running or a wrong PIN was entered recently");
	}
	pin_attempt(const pin_attempt &) = delete;
	pin_attempt & operator=(const pin_attempt &) = delete;

	void set_correct()
	{
		correct = true;
	}

	// An abandoned check counts as wrong: it may have been a guess
	~pin_attempt()
	{
		auto delay = pin_attempts.end(correct);
		if (not correct)
			std::cerr << "Next PIN check allowed in " << delay << std::endl;
	}
};
} // namespace

wivrn::authenticated_peer wivrn::wivrn_connection::authenticate_peer(std::stop_token stop_token, TCP && tcp, const std::function<void(bool)> & waiting) const
{
	return authenticate(stop_token, state, pin, std::move(tcp), waiting);
}

wivrn::authenticated_peer wivrn::wivrn_connection::authenticate(std::stop_token stop_token, encryption_state state, const std::string & pin, TCP && tcp, const std::function<void(bool)> & waiting)
{
	typed_socket<TCP, from_headset::packets, to_headset::packets> control(std::move(tcp));
	// Handshake packets are a few KiB. Up to handshake_pool::max_attempts peers authenticate at
	// once, so do not let each one make the server allocate a full-size record buffer.
	control.set_max_payload(authenticate_max_payload);

	auto receive = [&](std::chrono::seconds timeout) {
		auto timeout_abs = std::chrono::steady_clock::now() + timeout;
		bool waited = false;
		auto got = [&](from_headset::packets && packet) {
			if (waited and waiting)
				waiting(false);
			return std::move(packet);
		};

		while (true)
		{
			// Data may already be buffered from an earlier read
			if (auto packet = control.receive_pending())
				return got(std::move(*packet));

			if (not waited and waiting)
				waiting(true);
			waited = true;

			if (stop_token.stop_requested())
				throw std::runtime_error("Connection cancelled");

			pollfd fds{.fd = control.get_fd(), .events = POLLIN};
			// Wake up at least every 100ms to check for cancellation
			if (::poll(&fds, 1, 100) < 0)
				throw std::system_error(errno, std::system_category());

			if (fds.revents & (POLLHUP | POLLERR))
				throw std::runtime_error("Error on control socket");

			if (fds.revents & POLLIN)
			{
				if (auto packet = control.receive())
					return got(std::move(*packet));
			}

			if (std::chrono::steady_clock::now() > timeout_abs)
				throw std::runtime_error("No handshake received from client");
		}
	};

	// Wait for client to send handshake packet
	auto crypto_handshake = std::get<from_headset::crypto_handshake>(receive(10s));

	if (crypto_handshake.protocol_version != wivrn::protocol_version)
	{
		control.send(to_headset::crypto_handshake{
		        .state = to_headset::crypto_handshake::crypto_state::incompatible_version,
		});
		throw std::runtime_error("Incompatible protocol version");
	}

	crypto::key headset_key = crypto::key::from_public_key(crypto_handshake.public_key);
	bool is_public_key_known = std::ranges::any_of(
	        wivrn::known_keys(),
	        [key = clean_key(crypto_handshake.public_key)](const wivrn::headset_key & k) {
		        return k.public_key == key;
	        });

	authenticated_peer peer{
	        .add_key = state == encryption_state::pairing and not is_public_key_known,
	        .public_key = clean_key(headset_key.public_key()),
	        .name = crypto_handshake.name,
	};

	switch (state)
	{
		case encryption_state::disabled:
			// Encryption and authentication are disabled
			control.send(to_headset::crypto_handshake{
			        .state = to_headset::crypto_handshake::crypto_state::encryption_disabled,
			});
			break;

		case encryption_state::enabled:
			if (not is_public_key_known)
			{
				control.send(to_headset::crypto_handshake{
				        .state = to_headset::crypto_handshake::crypto_state::pairing_disabled,
				});
				throw std::runtime_error("Client not known and pairing is disabled");
			}

			[[fallthrough]];

		case encryption_state::pairing:
			// Generate an ephemeral key pair just for exchanging the AES key
			crypto::key server_key = crypto::key::generate_x448_keypair();
			// Long-term key the headset pins at pairing, so it can tell this server from an impostor
			crypto::key identity_key = [&] {
				std::lock_guard lock(identity_key_mutex);
				return wivrn::identity_key_or_notify(
				        wivrn::server_identity_key,
				        [&](auto && packet) { control.send(std::forward<decltype(packet)>(packet)); });
			}();

			control.send(to_headset::crypto_handshake{
			        .public_key = server_key.public_key(),
			        .state = is_public_key_known
			                         ? to_headset::crypto_handshake::crypto_state::client_already_paired
			                         : to_headset::crypto_handshake::crypto_state::pin_needed,
			        .identity_key = identity_key.public_key(),
			});

			if (not is_public_key_known)
			{
				try
				{
					// Check the PIN. The wait is long because the user types the PIN now; it
					// holds no shared slot, other headsets keep connecting meanwhile.
					crypto::smp pin_check;

					auto msg1 = std::get<from_headset::pin_check_1>(receive(2min)).message;

					// Throttled from here: the peer learns whether its PIN matched from pin_check_4
					pin_attempt attempt(stop_token, waiting);

					auto msg2 = pin_check.step2(msg1, pin_check_secret(pin, identity_key, headset_key));
					control.send(to_headset::pin_check_2{msg2});

					// Short: the headset answers at once, and a peer stalling here holds the only
					// PIN check while other headsets wait for it (pin_attempt waits 8s at most)
					auto msg3 = std::get<from_headset::pin_check_3>(receive(5s)).message;

					auto [msg4, pin_match] = pin_check.step4(msg3);
					control.send(to_headset::pin_check_4{msg4});

					if (not pin_match)
						throw incorrect_pin{};

					attempt.set_correct();
				}
				catch (crypto::smp_cheated &)
				{
					throw std::runtime_error("Unable to check PIN");
				}
			}

			peer.keys = secrets::server(server_key, identity_key, headset_key, is_public_key_known ? "000000" : pin);
			control.set_aes_key_and_ivs(peer.keys->control_key, peer.keys->control_iv_from_headset, peer.keys->control_iv_to_headset);
			break;
	}

	// Wait for confirmation that the client has set up encryption: only a peer holding the paired
	// key (or the PIN) can send it, so the handshake is authenticated from here on
	if (not std::holds_alternative<from_headset::crypto_handshake>(receive(10s)))
		throw std::runtime_error("No handshake received from client");

	control.set_max_payload(TCP::default_max_payload);
	peer.control = std::move(control);
	return peer;
}

void wivrn::wivrn_connection::init(std::stop_token stop_token, authenticated_peer && peer, std::function<void()> tick)
{
	active = false;

	control = std::move(peer.control);

	sockaddr_in6 server_address;
	socklen_t len = sizeof(server_address);
	if (getsockname(control.get_fd(), (sockaddr *)&server_address, &len) < 0)
	{
		throw std::system_error(errno, std::system_category(), "Cannot get socket port");
	}
	int port = ntohs(((struct sockaddr_in6 *)&server_address)->sin6_port);

	sockaddr_in6 client_address;
	len = sizeof(client_address);
	if (getpeername(control.get_fd(), (sockaddr *)&client_address, &len) < 0)
	{
		throw std::system_error(errno, std::system_category(), "Cannot get client address");
	}

	if (configuration().tcp_only)
	{
		port = -1;
	}
	else
	{
		stream = decltype(stream)();
		stream.bind(server_address);
		if (peer.keys)
			stream.set_aes_key_and_ivs(peer.keys->stream_key, peer.keys->stream_iv_header_from_headset, peer.keys->stream_iv_header_to_headset);
	}

	auto receive = [&](std::optional<std::chrono::seconds> timeout = std::nullopt, bool allow_stream_socket = false) {
		// Returns the packet and the port (on the stream socket) or -1 (on the control socket)

		std::chrono::steady_clock::time_point timeout_abs{};
		if (timeout)
			timeout_abs = std::chrono::steady_clock::now() + *timeout;

		while (true)
		{
			if (stop_token.stop_requested())
				throw std::runtime_error("Connection cancelled");

			tick();

			pollfd fds[3] = {};
			if (allow_stream_socket)
			{
				fds[0].events = POLLIN;
				fds[0].fd = stream.get_fd();
			}
			fds[1].events = POLLIN;
			fds[1].fd = control.get_fd();
			fds[2].events = POLLIN;
			fds[2].fd = wivrn_ipc_socket_monado->get_fd();

			// Make sure tick() is called at least every 100ms
			int r = ::poll(fds, std::size(fds), 100);
			if (r < 0)
				throw std::system_error(errno, std::system_category());

			if (allow_stream_socket and (fds[0].revents & (POLLHUP | POLLERR)))
				throw std::runtime_error("Error on stream socket");

			if (fds[1].revents & (POLLHUP | POLLERR))
				throw std::runtime_error("Error on control socket");

			if (fds[2].revents & (POLLHUP | POLLERR))
				throw std::runtime_error("Error on IPC socket");

			if (allow_stream_socket and (fds[0].revents & POLLIN))
			{
				auto [raw_packet, peer_addr] = stream.receive_from_raw();

				// Ignore packets sent from the wrong address
				if (memcmp(&peer_addr.sin6_addr, &client_address.sin6_addr, sizeof(peer_addr.sin6_addr)) == 0)
					return std::make_pair(raw_packet.deserialize<from_headset::packets>(), (int)htons(peer_addr.sin6_port));
			}

			if (fds[1].revents & POLLIN)
			{
				std::optional<from_headset::packets> packet = control.receive();
				if (packet)
					return std::make_pair(std::move(*packet), -1);
			}

			if (fds[2].revents & POLLIN)
			{
				auto packet = receive_from_main();
				if (packet)
					std::visit([](auto && x) { handle_event_from_main_loop(x); }, *packet);
			}

			if (timeout and std::chrono::steady_clock::now() > timeout_abs)
			{
				throw std::runtime_error("No handshake received from client");
			}
		}
	};

	control.send(to_headset::handshake{.stream_port = port});

	auto [stream_handshake, client_port] = receive(10s, true);

	// Check the packet type
	if (not std::holds_alternative<from_headset::handshake>(stream_handshake))
	{
		throw std::runtime_error("No handshake received from client");
	}

	if (client_port >= 0)
	{
		client_address.sin6_port = htons(client_port);
		stream.connect(client_address);
		stream.set_send_buffer_size(1024 * 1024 * 5);
	}
	else
	{
		// No stream socket
		stream = decltype(stream)(-1);
	}

	control.send(to_headset::handshake{.stream_port = port});

	info_packet = std::get<from_headset::headset_info_packet>(receive(10s).first);

	active = true;

	if (peer.add_key)
		wivrn::add_known_key({
		        .public_key = peer.public_key,
		        .name = peer.name,
		});
	else if (peer.keys)
		wivrn::update_last_connection_timestamp(peer.public_key);
}

void wivrn::wivrn_connection::reset(std::stop_token stop, authenticated_peer && peer, std::function<void()> tick)
{
	if (stream)
		stream = decltype(stream)();

	init(stop, std::move(peer), tick);
}

void wivrn::wivrn_connection::shutdown()
{
	if (stream)
		::shutdown(stream.get_fd(), SHUT_RDWR);
	if (control)
		::shutdown(control.get_fd(), SHUT_RDWR);
}

std::optional<wivrn::from_headset::packets> wivrn::wivrn_connection::poll_control(int timeout)
{
	pollfd fds{};
	fds.events = POLLIN;
	fds.fd = control.get_fd();

	int r = ::poll(&fds, 1, timeout);
	if (r < 0)
		throw std::system_error(errno, std::system_category());

	if (r > 0 && (fds.revents & POLLIN))
	{
		return control.receive();
	}

	return {};
}
