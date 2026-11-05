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

#pragma once

#include "crypto.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct secrets
{
	std::array<std::uint8_t, 16> control_key;
	std::array<std::uint8_t, 16> control_iv_to_headset;
	std::array<std::uint8_t, 16> control_iv_from_headset;

	std::array<std::uint8_t, 16> stream_key;
	std::array<std::uint8_t, 8> stream_iv_header_to_headset;
	std::array<std::uint8_t, 8> stream_iv_header_from_headset;

	// Session keys for an authenticated handshake.
	// The headset authenticates with its static key (pinned by the server in known_keys), the
	// server with its long-term identity key (pinned by the headset at pairing). Keys are derived
	// from DH(headset, server ephemeral) || DH(headset, server identity), so only a peer holding
	// the pinned private key can compute them.
	static secrets headset(crypto::key & headset_key, crypto::key & server_ephemeral, crypto::key & server_identity, const std::string & pin);
	static secrets server(crypto::key & server_ephemeral, crypto::key & server_identity, crypto::key & headset_key, const std::string & pin);

private:
	secrets(std::vector<uint8_t> dh, const std::string & pin);
};

// Secret compared by the PIN check (SMP). It binds the PIN to both long-term public keys, so a
// relay sitting between the headset and the real server sees a mismatch instead of a successful
// PIN check it could brute-force offline.
std::string pin_check_secret(const std::string & pin, const crypto::key & server_identity, const crypto::key & headset_key);
