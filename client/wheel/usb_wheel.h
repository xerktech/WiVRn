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

// A G920 in HID mode, driven through a usbfs file descriptor (Android's
// UsbDeviceConnection, or /dev/bus/usb on Linux). The descriptor stays owned by the
// caller and must outlive this object.

#pragma once

#include "g920.h"
#include "wivrn_packets.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <thread>

namespace wheel
{

// Sends the mode switch message to a G920 in Xbox mode; the device then disconnects and
// comes back as 046d:c262. Returns false if the device has no vendor OUT endpoint or the
// transfer failed.
bool mode_switch(int fd);

// Log every force feedback request and its result (the "Log wheel force feedback" setting)
inline std::atomic_bool log_ff = false;

class usb_wheel
{
public:
	using sink = std::function<void(wivrn::from_headset::packets &&)>;

	// Claims the HID interface (detaching the kernel driver) and starts reading. Throws
	// std::runtime_error if the device can't be used. send is called from the reading
	// thread, never after the destructor returns.
	usb_wheel(int fd, uint8_t id, uint16_t vendor, uint16_t product, std::string name, sink send);
	~usb_wheel();

	usb_wheel(const usb_wheel &) = delete;
	usb_wheel & operator=(const usb_wheel &) = delete;

	const wivrn::from_headset::wheel_added & description() const
	{
		return added;
	}

	// Queues a force feedback request; never blocks on the device
	void ff(const wivrn::to_headset::wheel_ff &);

	// The device stopped answering (unplugged): the owner should destroy this object
	bool gone() const
	{
		return disconnected;
	}

private:
	int fd;
	uint8_t id; // also in added, which the reading thread may not read before it is announced
	usb_layout usb;
	input_layout layout;
	wivrn::from_headset::wheel_added added;
	sink send;

	std::atomic_bool quit = false;
	std::atomic_bool announced = false; // wheel_added sent: state may go out
	std::atomic_bool disconnected = false;

	// HID++ replies, handed from the reading thread to the FF thread
	std::mutex reply_mutex;
	std::condition_variable reply_cv;
	std::optional<hidpp::reply> last_reply;

	// Force feedback state, only used by the FF thread (after the constructor)
	std::optional<uint8_t> ff_index;
	uint8_t ff_effects_max = 0;
	std::map<int16_t, uint8_t> slots; // server effect id -> device slot
	std::optional<uint8_t> autocenter_slot;

	std::mutex ff_mutex;
	std::condition_variable ff_cv;
	std::deque<wivrn::to_headset::wheel_ff> ff_queue;

	std::thread reader;
	std::thread ff_thread;

	void claim();
	void release();
	std::vector<uint8_t> read_report_descriptor();

	bool write(std::span<const uint8_t> report);
	// Sends a request on the FF feature and waits for its reply
	std::optional<hidpp::reply> call(uint8_t feature_index, uint8_t function, std::span<const uint8_t> params);
	void init_ff();
	void apply(const wivrn::to_headset::wheel_ff &);

	void read_loop();
	void ff_loop();
};

} // namespace wheel
