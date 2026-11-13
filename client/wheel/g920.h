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

// Device-independent parts of the Logitech G920 driver (XERK-2851): HID report
// descriptor parsing, input report decoding into Linux input codes, and HID++ 2.0
// force feedback (feature 0x8123) message encoding. No I/O here, so it is unit tested
// on the host (client/tests/wheel_ut.cpp).

#pragma once

#include "wivrn_packets.h"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace wheel
{

constexpr uint16_t logitech_vendor = 0x046d;
// Before the mode switch the G920 enumerates as an Xbox One controller
constexpr uint16_t g920_xbox_product = 0xc261;
constexpr uint16_t g920_hid_product = 0xc262;

// Bulk/interrupt OUT message that makes the Xbox-mode G920 re-enumerate in HID mode
// (the same bytes usb_modeswitch sends for 046d:c261).
constexpr std::array<uint8_t, 5> g920_mode_switch_message{0x0f, 0x00, 0x01, 0x01, 0x42};

// What the driver needs from the device's USB descriptors
struct usb_layout
{
	struct endpoint
	{
		uint8_t address = 0;
		uint16_t max_packet = 0;
	};
	struct hid_interface
	{
		uint8_t number;
		uint16_t report_descriptor_length;
		endpoint in;
		std::optional<endpoint> out;
	};
	struct vendor_interface
	{
		uint8_t number;
		endpoint out;
	};
	std::optional<hid_interface> hid;       // first HID interface with an interrupt IN endpoint
	std::optional<vendor_interface> vendor; // first vendor-class interface with an OUT endpoint (Xbox mode)
};

// Parses a configuration descriptor and what follows it (interfaces, class descriptors,
// endpoints), as read from usbfs after the 18-byte device descriptor.
usb_layout parse_usb_configuration(std::span<const uint8_t> descriptors);

// A field of an input report, mapped to a Linux input code the way the kernel's generic
// hid-input driver maps it, so the server's virtual wheel looks like the device would on
// a Linux host.
struct input_field
{
	enum class kind : uint8_t
	{
		axis,
		button,
		hat, // one field, two axes: ABS_HAT0X and ABS_HAT0Y
	};
	kind type;
	uint16_t code; // ABS_* or BTN_*; for a hat, ABS_HAT0X
	uint8_t report_id;
	uint32_t bit_offset; // from the start of the report data, after the report id byte
	uint32_t bit_size;
	int32_t logical_min;
	int32_t logical_max;
};

struct input_layout
{
	bool report_ids = false; // reports start with a report id byte
	std::vector<input_field> fields;

	// Axes and keys as declared in wheel_added, in field order
	std::vector<wivrn::from_headset::wheel_added::axis> axes() const;
	std::vector<uint16_t> keys() const;
};

// Parses a HID report descriptor. Fields of vendor pages (such as HID++ reports) and
// constant padding are left out. Returns nothing for a malformed descriptor or one
// without any axis or button.
std::optional<input_layout> parse_report_descriptor(std::span<const uint8_t> descriptor);

// Current values of the wheel's inputs
struct input_state
{
	std::vector<int32_t> axes; // same order as input_layout::axes()
	std::vector<uint8_t> keys; // bitmap, same order as input_layout::keys()

	bool operator==(const input_state &) const = default;
};

input_state initial_state(const input_layout &);

// Decodes an input report (starting with its report id byte if the layout has ids) into
// state. Returns false if the report is not an input report of this layout.
bool decode_report(const input_layout &, std::span<const uint8_t> report, input_state & state);

// wheel_state with the axes that differ from before, and every key
wivrn::from_headset::wheel_state diff(uint8_t id, const input_layout &, const input_state & before, const input_state & after);

namespace hidpp
{
constexpr uint8_t report_short = 0x10;
constexpr uint8_t report_long = 0x11;
constexpr uint8_t report_very_long = 0x12;
constexpr size_t long_length = 20;
constexpr size_t very_long_length = 64;
// Device index for a device on its own USB connection (no receiver)
constexpr uint8_t device_index = 0xff;
// Software id, returned in replies so they can be matched to requests
constexpr uint8_t software_id = 0x0e;
constexpr uint8_t error_feature = 0xff;

constexpr uint16_t root_feature = 0x0000;
constexpr uint16_t force_feedback_feature = 0x8123;

// A long report, or a very long one when params don't fit
std::vector<uint8_t> request(uint8_t feature_index, uint8_t function, std::span<const uint8_t> params);

// IRoot.getFeature: the reply's first parameter is the feature's index
std::vector<uint8_t> get_feature(uint16_t feature);

struct reply
{
	uint8_t feature_index;
	uint8_t function;
	bool error;
	uint8_t error_code;
	std::array<uint8_t, 16> params;
};

// Parses a HID++ reply sent with our software id; nothing for anything else (input
// reports, notifications, replies to another software id)
std::optional<reply> parse_reply(std::span<const uint8_t> report);

// Force feedback feature functions
namespace ff
{
enum function : uint8_t
{
	get_info = 0,
	reset_all = 1,
	download_effect = 2,
	set_effect_state = 3,
	destroy_effect = 4,
	get_aperture = 5,
	set_aperture = 6,
	get_global_gains = 7,
	set_global_gains = 8,
};

enum effect_state : uint8_t
{
	state_stop = 1,
	state_play = 2,
};

enum effect_type : uint8_t
{
	type_constant = 0x00,
	type_sine = 0x01,
	type_square = 0x02,
	type_triangle = 0x03,
	type_sawtooth_up = 0x04,
	type_sawtooth_down = 0x05,
	type_spring = 0x06,
	type_damper = 0x07,
	type_friction = 0x08,
	type_inertia = 0x09,
	type_ramp = 0x0a,
	autostart = 0x80,
};

// Parameters of download_effect for a Linux effect. slot is the device slot to replace,
// 0 for a new effect. Nothing for an effect the wheel can't play (rumble, custom).
std::optional<std::vector<uint8_t>> download_params(uint8_t slot, const wivrn::wheel_ff_effect &);

// The autocenter spring the kernel driver uses: full saturation, a quarter of the
// coefficient range at magnitude 0xffff, started at once
std::vector<uint8_t> autocenter_params(uint16_t magnitude);

std::vector<uint8_t> gain_params(uint16_t gain);

// Effect types the wheel plays, as Linux FF_* codes, plus FF_GAIN and FF_AUTOCENTER
std::vector<uint16_t> supported_effects();
} // namespace ff
} // namespace hidpp

// One-line description of a wheel_ff request, for the FF debug log
std::string describe(const wivrn::to_headset::wheel_ff &);

} // namespace wheel
