/*
 * WiVRn VR streaming
 * Copyright (C) 2022-2024  Guillaume Meunier <guillaume.meunier@centraliens.net>
 * Copyright (C) 2022-2024  Patrick Nicolas <patricknicolas@laposte.net>
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

#include "driver/wivrn_connection.h"

#include <functional>
#include <optional>
#include <stop_token>

namespace wivrn
{
class handshake_gate;
class wivrn_session;
// Waits for a headset to authenticate on gate. The gate is owned by the caller so it outlives a
// handshake that fails later: other peers queued in it are not dropped.
// Returns nothing when stopped.
std::optional<authenticated_peer> accept_connection(
        wivrn_session & cnx,
        std::stop_token stop,
        handshake_gate & gate,
        std::function<authenticated_peer(std::stop_token, TCP &&, const std::function<void(bool)> &)> authenticate,
        std::function<void(wivrn_session &)> tick = {});
} // namespace wivrn
