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

// G920 driver logic (XERK-2851): report descriptor, input decoding, HID++ FF encoding.

#include "../wheel/g920.h"

#include <cstdio>
#include <cstdlib>
#include <linux/input.h>

static int failures = 0;

#define CHECK(cond)                                                                                   \
	do                                                                                            \
	{                                                                                             \
		if (not(cond))                                                                        \
		{                                                                                     \
			std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
			++failures;                                                                   \
		}                                                                                     \
	} while (0)

// A G920-shaped descriptor: joystick application, report 1 with a 16-bit X, a hat,
// 12 buttons, a padding byte, then three 8-bit pedals (Y, Z, Rz); report 0x11 is HID++ (vendor
// page, must be ignored).
static const std::vector<uint8_t> descriptor{
        0x05,
        0x01, // Usage Page (Generic Desktop)
        0x09,
        0x04, // Usage (Joystick)
        0xa1,
        0x01, // Collection (Application)
        0x85,
        0x01, //   Report ID 1
        0x09,
        0x30, //   Usage (X)
        0x15,
        0x00, //   Logical Minimum 0
        0x27,
        0xff,
        0xff,
        0x00,
        0x00, // Logical Maximum 65535
        0x75,
        0x10, //   Report Size 16
        0x95,
        0x01, //   Report Count 1
        0x81,
        0x02, //   Input (Data, Var, Abs)
        0x09,
        0x39, //   Usage (Hat switch)
        0x15,
        0x00, //   Logical Minimum 0
        0x25,
        0x07, //   Logical Maximum 7
        0x75,
        0x04, //   Report Size 4
        0x95,
        0x01, //   Report Count 1
        0x81,
        0x42, //   Input (Data, Var, Abs, Null)
        0x05,
        0x09, //   Usage Page (Button)
        0x19,
        0x01, //   Usage Minimum 1
        0x29,
        0x0c, //   Usage Maximum 12
        0x15,
        0x00, //   Logical Minimum 0
        0x25,
        0x01, //   Logical Maximum 1
        0x75,
        0x01, //   Report Size 1
        0x95,
        0x0c, //   Report Count 12
        0x81,
        0x02, //   Input (Data, Var, Abs)
        0x75,
        0x08, //   Report Size 8
        0x95,
        0x01, //   Report Count 1
        0x81,
        0x01, //   Input (Const) padding
        0x05,
        0x01, //   Usage Page (Generic Desktop)
        0x09,
        0x31, //   Usage (Y)
        0x09,
        0x32, //   Usage (Z)
        0x09,
        0x35, //   Usage (Rz)
        0x15,
        0x00, //   Logical Minimum 0
        0x26,
        0xff,
        0x00, //   Logical Maximum 255
        0x75,
        0x08, //   Report Size 8
        0x95,
        0x03, //   Report Count 3
        0x81,
        0x02, //   Input (Data, Var, Abs)
        0xc0, // End Collection
        0x06,
        0x43,
        0xff, // Usage Page (Vendor 0xff43)
        0x0a,
        0x02,
        0x06, // Usage 0x0602
        0xa1,
        0x01, // Collection (Application)
        0x85,
        0x11, //   Report ID 0x11
        0x75,
        0x08, //   Report Size 8
        0x95,
        0x13, //   Report Count 19
        0x15,
        0x00, //   Logical Minimum 0
        0x26,
        0xff,
        0x00, //   Logical Maximum 255
        0x09,
        0x02, //   Usage 2
        0x81,
        0x00, //   Input (Data, Array)
        0x09,
        0x02, //   Usage 2
        0x91,
        0x00, //   Output (Data, Array)
        0xc0, // End Collection
};

static void test_descriptor()
{
	auto layout = wheel::parse_report_descriptor(descriptor);
	CHECK(layout);
	if (not layout)
		return;
	CHECK(layout->report_ids);

	auto axes = layout->axes();
	CHECK(axes.size() == 6);
	if (axes.size() == 6)
	{
		CHECK(axes[0].code == ABS_X and axes[0].min == 0 and axes[0].max == 65535);
		CHECK(axes[1].code == ABS_HAT0X and axes[1].min == -1 and axes[1].max == 1);
		CHECK(axes[2].code == ABS_HAT0Y);
		CHECK(axes[3].code == ABS_Y and axes[3].max == 255);
		CHECK(axes[4].code == ABS_Z);
		CHECK(axes[5].code == ABS_RZ);
	}

	auto keys = layout->keys();
	CHECK(keys.size() == 12);
	if (keys.size() == 12)
	{
		CHECK(keys[0] == BTN_TRIGGER);
		CHECK(keys[11] == BTN_JOYSTICK + 11);
	}
}

static void test_bad_descriptors()
{
	// Truncated in the middle of an item
	std::vector<uint8_t> truncated(descriptor.begin(), descriptor.begin() + 13);
	CHECK(not wheel::parse_report_descriptor(truncated));

	// Report id 0 is reserved
	CHECK(not wheel::parse_report_descriptor(std::vector<uint8_t>{0x85, 0x00}));

	// Unbalanced end collection, pop without push
	CHECK(not wheel::parse_report_descriptor(std::vector<uint8_t>{0xc0}));
	CHECK(not wheel::parse_report_descriptor(std::vector<uint8_t>{0xb4}));

	// Vendor-only (the HID++ part): nothing to forward
	std::vector<uint8_t> vendor(descriptor.end() - 28, descriptor.end());
	CHECK(vendor[0] == 0x06);
	CHECK(not wheel::parse_report_descriptor(vendor));

	CHECK(not wheel::parse_report_descriptor({}));
}

static void test_decode()
{
	auto layout = *wheel::parse_report_descriptor(descriptor);
	auto before = wheel::initial_state(layout);
	auto state = before;

	// X = 0x1234, hat = 2 (right), buttons 1 and 12, pedals 0x10 0x20 0x30
	std::vector<uint8_t> report{0x01, 0x34, 0x12, 0x02 | (1 << 4), 0x80, 0x00, 0x10, 0x20, 0x30};
	CHECK(wheel::decode_report(layout, report, state));
	CHECK(state.axes == (std::vector<int32_t>{0x1234, 1, 0, 0x10, 0x20, 0x30}));
	CHECK(state.keys == (std::vector<uint8_t>{0x01, 0x08}));

	auto d = wheel::diff(3, layout, before, state);
	CHECK(d.id == 3);
	CHECK(d.axes.size() == 5); // hat Y stayed 0
	CHECK(d.keys == state.keys);

	// Hat null state (8) is centered, button 1 released
	before = state;
	report = {0x01, 0x34, 0x12, 0x08, 0x80, 0x00, 0x10, 0x20, 0x30};
	CHECK(wheel::decode_report(layout, report, state));
	CHECK(state.axes[1] == 0 and state.axes[2] == 0);
	CHECK(state.keys[0] == 0x00);
	d = wheel::diff(3, layout, before, state);
	CHECK(d.axes.size() == 1 and d.axes[0].code == ABS_HAT0X);

	// HID++ report and empty report are not input
	auto copy = state;
	std::vector<uint8_t> hidpp(20, 0);
	hidpp[0] = 0x11;
	CHECK(not wheel::decode_report(layout, hidpp, state));
	CHECK(not wheel::decode_report(layout, {}, state));
	CHECK(state == copy);

	// A short report only updates the fields it holds
	report = {0x01, 0xff, 0xff};
	CHECK(wheel::decode_report(layout, report, state));
	CHECK(state.axes[0] == 0xffff and state.axes[3] == 0x10);
}

static void test_hidpp()
{
	auto msg = wheel::hidpp::get_feature(0x8123);
	CHECK(msg.size() == 20);
	CHECK(msg[0] == 0x11 and msg[1] == 0xff and msg[2] == 0x00 and msg[3] == wheel::hidpp::software_id);
	CHECK(msg[4] == 0x81 and msg[5] == 0x23);

	std::vector<uint8_t> reply(20, 0);
	reply[0] = 0x11;
	reply[1] = 0xff;
	reply[2] = 0x00;
	reply[3] = wheel::hidpp::software_id;
	reply[4] = 0x0b;
	auto r = wheel::hidpp::parse_reply(reply);
	CHECK(r and not r->error and r->feature_index == 0 and r->function == 0 and r->params[0] == 0x0b);

	// Another software id (e.g. a notification) is not ours
	reply[3] = 0x00;
	CHECK(not wheel::hidpp::parse_reply(reply));

	// Error reply
	reply = std::vector<uint8_t>(20, 0);
	reply[0] = 0x11;
	reply[1] = 0xff;
	reply[2] = 0xff;
	reply[3] = 0x0b;
	reply[4] = (2 << 4) | wheel::hidpp::software_id;
	reply[5] = 0x05;
	r = wheel::hidpp::parse_reply(reply);
	CHECK(r and r->error and r->feature_index == 0x0b and r->function == 2 and r->error_code == 5);

	// Input report, short garbage
	CHECK(not wheel::hidpp::parse_reply(std::vector<uint8_t>{0x01, 0, 0, 0, 0, 0, 0, 0}));
	CHECK(not wheel::hidpp::parse_reply(std::vector<uint8_t>{0x11, 0xff}));
}

static void test_ff()
{
	using namespace wheel::hidpp::ff;

	// Constant force to the right (direction 0xc000: sin = -1)
	wivrn::wheel_ff_effect e{
	        .type = FF_CONSTANT,
	        .direction = 0xc000,
	        .replay_length = 0x1234,
	        .replay_delay = 5,
	        .u = wivrn::wheel_ff_effect::constant{.level = 0x4000, .envelope = {.attack_length = 0x0102, .attack_level = 0x7fff}},
	};
	auto p = download_params(3, e);
	CHECK(p and p->size() == 14);
	if (p and p->size() == 14)
	{
		CHECK((*p)[0] == 3 and (*p)[1] == type_constant);
		CHECK((*p)[2] == 0x12 and (*p)[3] == 0x34 and (*p)[4] == 0 and (*p)[5] == 5);
		CHECK((*p)[6] == 0xc0 and (*p)[7] == 0x00); // -0x4000
		CHECK((*p)[8] == 0xff and (*p)[9] == 0x01 and (*p)[10] == 0x02);
		auto msg = wheel::hidpp::request(7, download_effect, *p);
		CHECK(msg.size() == 20 and msg[0] == 0x11 and msg[2] == 7 and msg[3] == ((2 << 4) | wheel::hidpp::software_id));
		CHECK(msg[4] == 3 and msg[10] == 0xc0);
	}

	// Variant not matching the type, rumble and custom waveforms are refused
	e.type = FF_SPRING;
	CHECK(not download_params(0, e));
	e.type = FF_RUMBLE;
	e.u = wivrn::wheel_ff_effect::rumble{1, 2};
	CHECK(not download_params(0, e));
	e.type = FF_PERIODIC;
	e.u = wivrn::wheel_ff_effect::periodic{.waveform = FF_CUSTOM};
	CHECK(not download_params(0, e));

	// Periodic: 20 params, needs a very long report
	e.direction = 0x4000; // sin = 1
	e.u = wivrn::wheel_ff_effect::periodic{.waveform = FF_SINE, .period = 100, .magnitude = 0x1000, .offset = -2, .phase = 0};
	p = download_params(0, e);
	CHECK(p and p->size() == 20);
	if (p and p->size() == 20)
	{
		CHECK((*p)[1] == type_sine);
		CHECK((*p)[6] == 0x10 and (*p)[7] == 0x00);
		CHECK((*p)[8] == 0xff and (*p)[9] == 0xfe);
		CHECK((*p)[10] == 0 and (*p)[11] == 100);
		auto msg = wheel::hidpp::request(7, download_effect, *p);
		CHECK(msg.size() == 64 and msg[0] == 0x12 and msg[23] == (*p)[19]);
	}

	// Spring
	e.type = FF_SPRING;
	e.u = std::array<wivrn::wheel_ff_effect::condition, 2>{wivrn::wheel_ff_effect::condition{
	        .right_saturation = 0xffff,
	        .left_saturation = 0x8000,
	        .right_coeff = 0x2000,
	        .left_coeff = -0x2000,
	        .deadband = 0x0200,
	        .center = 0x0100,
	}};
	p = download_params(0, e);
	CHECK(p and p->size() == 18);
	if (p and p->size() == 18)
	{
		CHECK((*p)[1] == type_spring);
		CHECK((*p)[6] == 0x40 and (*p)[7] == 0x00);   // left saturation 0x8000 >> 1
		CHECK((*p)[8] == 0xe0 and (*p)[9] == 0x00);   // left coeff
		CHECK((*p)[10] == 0x01 and (*p)[11] == 0x00); // deadband 0x200 >> 1
		CHECK((*p)[12] == 0x01 and (*p)[13] == 0x00); // center
		CHECK((*p)[14] == 0x20 and (*p)[15] == 0x00); // right coeff
		CHECK((*p)[16] == 0x7f and (*p)[17] == 0xff); // right saturation
	}

	auto a = autocenter_params(0xffff);
	CHECK(a.size() == 18 and a[1] == (type_spring | autostart));
	CHECK(a[6] == 0x7f and a[7] == 0xff and a[8] == 0x1f and a[9] == 0xff);
	CHECK(a[14] == 0x1f and a[15] == 0xff and a[16] == 0x7f and a[17] == 0xff);

	auto g = gain_params(0xabcd);
	CHECK(g.size() == 4 and g[0] == 0xab and g[1] == 0xcd);

	wivrn::to_headset::wheel_ff ff{.id = 1, .op = wivrn::to_headset::wheel_ff::operation::play, .effect_id = 4, .value = 1};
	CHECK(wheel::describe(ff) == "wheel 1 ff play effect=4 value=1");
}

static void test_usb_configuration()
{
	// HID mode: configuration, HID interface 0 with HID descriptor (report descriptor
	// 0x00a5 bytes), interrupt IN 0x81 (64), interrupt OUT 0x01 (64)
	std::vector<uint8_t> hid_mode{
	        9,
	        2,
	        41,
	        0,
	        1,
	        1,
	        0,
	        0x80,
	        0xfa,
	        9,
	        4,
	        0,
	        0,
	        2,
	        3,
	        0,
	        0,
	        0,
	        9,
	        0x21,
	        0x11,
	        0x01,
	        0,
	        1,
	        0x22,
	        0xa5,
	        0x00,
	        7,
	        5,
	        0x81,
	        3,
	        64,
	        0,
	        1,
	        7,
	        5,
	        0x01,
	        3,
	        64,
	        0,
	        1,
	};
	auto usb = wheel::parse_usb_configuration(hid_mode);
	CHECK(usb.hid and not usb.vendor);
	if (usb.hid)
	{
		CHECK(usb.hid->number == 0 and usb.hid->report_descriptor_length == 0xa5);
		CHECK(usb.hid->in.address == 0x81 and usb.hid->in.max_packet == 64);
		CHECK(usb.hid->out and usb.hid->out->address == 0x01);
	}

	// Xbox mode: vendor interface with interrupt OUT 0x01 and IN 0x81
	std::vector<uint8_t> xbox_mode{
	        9,
	        2,
	        32,
	        0,
	        1,
	        1,
	        0,
	        0x80,
	        0xfa,
	        9,
	        4,
	        0,
	        0,
	        2,
	        0xff,
	        0x47,
	        0xd0,
	        0,
	        7,
	        5,
	        0x81,
	        3,
	        64,
	        0,
	        4,
	        7,
	        5,
	        0x01,
	        3,
	        64,
	        0,
	        4,
	};
	usb = wheel::parse_usb_configuration(xbox_mode);
	CHECK(not usb.hid and usb.vendor and usb.vendor->number == 0 and usb.vendor->out.address == 0x01);

	// Truncated or zero-length descriptors don't loop or read out of bounds
	CHECK(not wheel::parse_usb_configuration(std::span(hid_mode).first(30)).hid);
	std::vector<uint8_t> zero{0, 4, 0, 0};
	CHECK(not wheel::parse_usb_configuration(zero).hid);
}

int main()
{
	test_usb_configuration();
	test_descriptor();
	test_bad_descriptors();
	test_decode();
	test_hidpp();
	test_ff();
	if (failures)
	{
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return EXIT_FAILURE;
	}
	std::puts("wheel_ut: all passed");
	return EXIT_SUCCESS;
}
