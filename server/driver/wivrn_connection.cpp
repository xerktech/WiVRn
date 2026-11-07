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
#include "wivrn_ipc.h"
#include "wivrn_packets.h"
#include <arpa/inet.h>
#include <chrono>
#include <poll.h>
#include <sys/socket.h>
#include <variant>

using namespace std::chrono_literals;

// Ignored until connection is established
static void handle_event_from_main_loop(to_monado::stop) {}
static void handle_event_from_main_loop(to_monado::disconnect) {}
static void handle_event_from_main_loop(to_monado::set_bitrate) {}
static void handle_event_from_main_loop(wivrn::to_headset::stream_tab_change) {}

wivrn::wivrn_connection::wivrn_connection(std::stop_token stop_token, encryption_state state, std::string pin, authenticated_peer && peer) :
        stream(-1),
        pin(pin),
        state(state)
{
	init(stop_token, std::move(peer));
}

wivrn::authenticated_peer wivrn::wivrn_connection::authenticate_peer(std::stop_token stop_token, TCP && tcp, const std::function<void(bool)> & waiting) const
{
	return wivrn::authenticate(stop_token, state, pin, std::move(tcp), waiting);
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

	// Like the server process (main.cpp headset_connected_success), leave pairing mode after any
	// successful connection, paired or not. This object moves into the forked session, whose
	// reconnects (authenticate_peer) would otherwise still pair any headset that knows the old PIN.
	if (state == encryption_state::pairing)
	{
		state = encryption_state::enabled;
		pin.clear();
	}
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
