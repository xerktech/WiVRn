/*
 * WiVRn VR streaming
 * Copyright (C) 2026  Patrick Nicolas <patricknicolas@laposte.net>
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

// Wheels plugged into the headset: tracks USB devices reported by the platform, switches
// a G920 to HID mode, and drives it while a stream runs (XERK-2851).

#pragma once

#include "usb_wheel.h"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace wheel
{

// How the manager reaches USB devices; set by the platform (client/android/usb_wheel.cpp)
struct platform
{
	// Asks the user for access to the device (system dialog)
	std::function<void(const std::string & device)> request_permission;
	// usbfs file descriptor, or -1
	std::function<int(const std::string & device)> open;
	std::function<void(const std::string & device)> close;
};

class manager
{
	struct device
	{
		uint16_t vendor;
		uint16_t product;
		std::string name;
		bool permission = false;
		bool permission_requested = false;
		bool mode_switched = false;
	};

	struct event
	{
		bool attached;
		std::string path;
		device dev;
	};

	std::mutex mutex;
	platform plat;
	std::vector<event> events;             // from the platform's thread, handled in poll
	std::map<std::string, device> devices; // by platform device path
	std::map<std::string, std::unique_ptr<usb_wheel>> wheels;
	std::optional<usb_wheel::sink> sink; // set while a stream runs
	bool enabled = true;

	void open_wheel(const std::string & path, const device &);
	// By value: callers pass the map's own key, which erasing the wheel frees
	void close_wheel(std::string path, bool send_removed);
	void handle(const std::string & path, device &);

public:
	static manager & instance();

	void set_platform(platform);

	// Platform callbacks, any thread
	void attached(std::string path, uint16_t vendor, uint16_t product, std::string name, bool permission);
	void detached(std::string path);

	// Called often from the application thread: handles platform events, unplugged wheels
	// and the setting
	void poll(bool enabled);

	// While a stream runs, wheels are opened and their packets go to send
	void start_stream(usb_wheel::sink send);
	// Releases every wheel; send is not called once this returns
	void stop_stream();

	void ff(const wivrn::to_headset::wheel_ff &);

	// Names of the wheels currently driven, for the stream GUI
	std::vector<std::string> connected();
};

} // namespace wheel
