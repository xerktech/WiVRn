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

#include "crypto.h"
#include "wivrn_packets.h"

#include <utility>

namespace wivrn
{
// Server side of the crypto handshake: load the long-term identity key the headset pins. If that
// fails (for example a corrupted server_key.pem), tell the headset with
// crypto_state::server_key_error before rethrowing, otherwise it only sees the connection drop.
// Tests: test_identity_key_error in common/test_handshake_crypto.cpp.
template <typename Load, typename Send>
crypto::key identity_key_or_notify(Load && load, Send && send)
{
	try
	{
		return std::forward<Load>(load)();
	}
	catch (...)
	{
		send(to_headset::crypto_handshake{
		        .state = to_headset::crypto_handshake::crypto_state::server_key_error,
		});
		throw;
	}
}
} // namespace wivrn
