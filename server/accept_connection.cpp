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

#include "accept_connection.h"

#include "util/u_logging.h"
#include "utils/overloaded.h"

#include "driver/configuration.h"
#include "driver/wivrn_session.h"
#include "handshake_pool.h"
#include "wivrn_ipc.h"
#include "wivrn_sockets.h"

#include <sys/poll.h>

std::optional<wivrn::authenticated_peer> wivrn::accept_connection(
        wivrn_session & cnx,
        std::stop_token stop,
        handshake_gate & listener,
        std::function<authenticated_peer(std::stop_token, TCP &&, const std::function<void(bool)> &)> authenticate,
        std::function<void(wivrn_session &)> tick)
{
	wivrn_ipc_socket_monado->send(from_monado::headset_disconnected{});

	// Peers whose first record has arrived authenticate concurrently, so a stalled or hostile one
	// cannot keep the headset out
	handshake_pool<authenticated_peer> handshakes;

	// The listener is not polled: when accept fails (e.g. out of descriptors) it stays readable and
	// would spin this loop; the gate is checked every 50ms instead, like in the main loop.
	pollfd fds[2]{
	        {.fd = -1},
	        {.fd = wivrn_ipc_socket_monado->get_fd(), .events = POLLIN},
	};

	while (not stop.stop_requested())
	{
		if (poll(fds, std::size(fds), 50) < 0)
		{
			perror("poll");
			return {};
		}

		while (true)
		{
			auto tcp = listener.poll();
			if (not tcp)
				break;
			handshakes.start(std::move(*tcp), authenticate);
		}

		if (auto peer = handshakes.take())
		{
			wivrn_ipc_socket_monado->send(from_monado::headset_connected{});
			return peer;
		}

		if (fds[1].revents & POLLIN)
		{
			auto packet = receive_from_main();
			if (packet)
				std::visit(utils::overloaded{
				                   [&cnx](to_monado::stop) {
					                   // gets handled in wivrn_session::reconnect since we return nullptr
					                   U_LOG_I("Received stop packet during reconnect, stopping");
					                   cnx.request_stop();
				                   },
				                   [](auto &&) {
					                   // Ignore request when no headset is connected
				                   },
				           },
				           *packet);
		}

		if (tick)
			tick(cnx);
	}

	return {};
}
