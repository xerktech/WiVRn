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

#include "authenticate.h"
#include "handshake_identity.h"
#include "handshake_pool.h"
#include "known_keys.h"
#include "protocol_version.h"
#include "smp.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <string_view>
#include <system_error>
#include <variant>

using namespace std::chrono_literals;

// Plain string processing rather than std::regex: handshakes run on concurrent threads, and
// libstdc++'s regex shares an unsynchronised ctype cache between them.
static std::string clean_key(const std::string & key)
{
	auto is_space = [](char c) { return c == ' ' or c == '\t' or c == '\n' or c == '\v' or c == '\f' or c == '\r'; };

	// A whole line of the form -+BEGIN .*-+ or -+END .*-+
	auto is_armour = [](std::string_view line) {
		size_t dashes = line.find_first_not_of('-');
		if (dashes == 0 or dashes == std::string_view::npos)
			return false;
		line.remove_prefix(dashes);
		if (not line.starts_with("BEGIN ") and not line.starts_with("END "))
			return false;
		return line.size() > 0 and line.back() == '-';
	};

	std::string result;
	result.reserve(key.size());

	std::string_view rest = key;
	while (not rest.empty())
	{
		size_t eol = rest.find_first_of("\r\n");
		std::string_view line = rest.substr(0, eol);
		rest.remove_prefix(eol == std::string_view::npos ? rest.size() : eol + 1);

		if (is_armour(line))
			continue;

		for (char c: line)
			if (not is_space(c))
				result += c;
	}

	return result;
}

wivrn::incorrect_pin::incorrect_pin() :
        std::runtime_error("Incorrect PIN") {}

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
	// The headset waits 10s for pin_check_4 (client/wivrn_client.cpp): wait for the running
	// check or the delay after a wrong PIN for less than that rather than refusing, so a user who
	// mistyped once just retries. The wait counts as waiting for the peer, so the handshake pool
	// can still cancel it to make room.
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

	// A check that fails after it began (bad pin_check_3, send error) counts as wrong
	~pin_attempt()
	{
		auto delay = pin_attempts.end(correct);
		if (not correct)
			std::cerr << "Next PIN check allowed in " << delay << std::endl;
	}
};
} // namespace

wivrn::authenticated_peer wivrn::authenticate(std::stop_token stop_token, encryption_state state, const std::string & pin, TCP && tcp, const std::function<void(bool)> & waiting)
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

					auto msg2 = pin_check.step2(msg1, pin_check_secret(pin, identity_key, headset_key));
					control.send(to_headset::pin_check_2{msg2});

					auto msg3 = std::get<from_headset::pin_check_3>(receive(10s)).message;

					// Throttled from here, after the last wait on the peer: it learns whether its PIN
					// matched only from pin_check_4, so a peer that stalls earlier learns nothing,
					// holds no throttle and does not count as a wrong PIN
					pin_attempt attempt(stop_token, waiting);

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
