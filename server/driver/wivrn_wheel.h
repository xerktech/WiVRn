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

// Wheels plugged into the headset (XERK-2850): each becomes a virtual input device on the
// server, either through fenrir's wheel helper (DIREWOLF_WHEEL_SOCKET) or local uinput, and
// the game's force-feedback requests are relayed back to the headset.
#pragma once

#include "wivrn_packets.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <linux/input.h>

namespace wivrn::wheel
{

// Limits shared with fenrir's wheel helper, which refuses anything outside them
constexpr size_t max_wheels = 4;
constexpr uint8_t max_ff_effects = 64;
constexpr size_t max_name_length = 79;

struct event
{
	uint16_t type;
	uint16_t code;
	int32_t value;
	bool operator==(const event &) const = default;
};

// A device sink for wheels. Calls may throw: the wheel is then recreated later.
class backend
{
public:
	virtual ~backend() = default;
	// desc has been through sanitize()
	virtual void create(const from_headset::wheel_added & desc) = 0;
	virtual void destroy(uint8_t id) = 0;
	// events end with a SYN_REPORT
	virtual void send(uint8_t id, std::span<const event> events) = 0;
	// Appends force-feedback requests, non-fatal errors, and wheels that no longer exist on the
	// backend's side (to be created again), since the last call
	virtual void poll(std::vector<to_headset::wheel_ff> & ff, std::vector<std::string> & errors, std::vector<uint8_t> & lost) = 0;
};

// fenrir's helper over a unix SOCK_SEQPACKET socket, one JSON object per packet.
// Connects on the first create, and again after the connection is lost.
std::unique_ptr<backend> make_helper_backend(std::string path);

// Drops what the headset may not create: unknown codes, more than the helper allows, a bad name.
// Keys that are dropped become 0 so wheel_state's key bitmap keeps its indices.
from_headset::wheel_added sanitize(from_headset::wheel_added desc);

// Kernel struct ff_effect -> packet; nullopt for effects that are not forwarded (FF_CUSTOM)
std::optional<wheel_ff_effect> from_kernel(const ff_effect & effect);

class manager
{
	struct device
	{
		from_headset::wheel_added desc; // sanitized
		std::vector<int32_t> abs;       // last value, indexed by axis code
		std::vector<bool> keys;         // last state, indexed like desc.keys
		bool created = false;
		std::chrono::steady_clock::time_point created_at{};
		std::chrono::steady_clock::time_point retry_at{};
		int failures = 0; // in a row: the backoff doubles, up to a minute
	};

	std::unique_ptr<backend> sink;
	std::map<uint8_t, device> devices;
	std::vector<std::string> errors;

	void try_create(device &);
	void fail(device &, const std::exception &);
	void back_off(device &);

public:
	explicit manager(std::unique_ptr<backend> sink);
	~manager();

	void add(from_headset::wheel_added desc);
	void remove(uint8_t id);
	void state(const from_headset::wheel_state & state);
	// Removes every wheel: the headset sends wheel_added again when it reconnects
	void clear();

	// Force-feedback requests to send to the headset, for wheels that still exist
	std::vector<to_headset::wheel_ff> poll_ff();
	// Errors since the last call, for the log
	std::vector<std::string> take_errors();

	size_t size() const
	{
		return devices.size();
	}
};

} // namespace wivrn::wheel
