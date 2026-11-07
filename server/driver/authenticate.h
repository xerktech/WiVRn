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

#include "secrets.h"
#include "wivrn_sockets.h"

#include <functional>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>

// First part of the server handshake, in its own file so it builds without the rest of the server.
// Tests: server/driver/authenticate_ut.cpp.
namespace wivrn
{
class incorrect_pin : public std::runtime_error
{
public:
	incorrect_pin();
};

enum class encryption_state
{
	disabled,
	enabled,
	pairing,
};

// Result of authenticate
struct authenticated_peer
{
	TCP control;          // Keys already set
	bool add_key = false; // Newly paired: store its key once the handshake completes
	std::string public_key;
	std::string name;
	std::optional<secrets> keys; // Empty when encryption is disabled
};

// Handshake up to the point where the peer has proven it holds a paired key (or the PIN). It only
// touches tcp, so several can run at once (see handshake_pool): a peer that stalls here cannot keep
// another headset out. Throws if the peer is refused.
// waiting is called with true when it starts waiting for the peer, false when data arrived.
authenticated_peer authenticate(std::stop_token stop_token, encryption_state state, const std::string & pin, TCP && tcp, const std::function<void(bool)> & waiting = {});
} // namespace wivrn
