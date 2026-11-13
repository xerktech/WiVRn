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

#include "g920.h"

#include <algorithm>
#include <cmath>
#include <linux/input.h>
#include <numbers>
#include <set>

#include <format>

namespace wheel
{

namespace
{
constexpr uint16_t page_generic_desktop = 0x01;
constexpr uint16_t page_simulation = 0x02;
constexpr uint16_t page_button = 0x09;

constexpr uint16_t usage_gamepad = 0x05;
constexpr uint16_t usage_hat_switch = 0x39;

// Abs code for an axis usage, as hid-input maps it; -1 if not an axis
int abs_code(uint16_t page, uint16_t usage)
{
	if (page == page_generic_desktop and usage >= 0x30 and usage <= 0x38)
		return usage & 0xf; // X Y Z Rx Ry Rz Slider Dial Wheel -> ABS_X .. ABS_WHEEL
	if (page == page_simulation)
	{
		switch (usage)
		{
			case 0xba:
				return ABS_RUDDER;
			case 0xbb:
				return ABS_THROTTLE;
			case 0xc4:
				return ABS_GAS;
			case 0xc5:
				return ABS_BRAKE;
			case 0xc8:
				return ABS_WHEEL;
		}
	}
	return -1;
}

int button_code(uint16_t application, uint16_t usage)
{
	if (usage == 0)
		return -1;
	int c = usage - 1;
	if (c > 0xf)
		return c - 0x10 + BTN_TRIGGER_HAPPY <= BTN_TRIGGER_HAPPY40 ? BTN_TRIGGER_HAPPY + c - 0x10 : -1;
	return (application == usage_gamepad ? BTN_GAMEPAD : BTN_JOYSTICK) + c;
}

struct globals
{
	uint16_t usage_page = 0;
	int32_t logical_min = 0;
	int32_t logical_max = 0;
	uint32_t report_size = 0;
	uint32_t report_count = 0;
	uint8_t report_id = 0;
};

int32_t sign_extend(uint32_t value, int bits)
{
	if (bits >= 32)
		return int32_t(value);
	uint32_t sign = 1u << (bits - 1);
	return int32_t((value ^ sign) - sign);
}

uint32_t extract(std::span<const uint8_t> data, uint32_t bit_offset, uint32_t bit_size)
{
	uint32_t value = 0;
	for (uint32_t i = 0; i < bit_size; ++i)
	{
		uint32_t bit = bit_offset + i;
		if (data[bit / 8] & (1u << (bit % 8)))
			value |= 1u << i;
	}
	return value;
}

void put16(std::vector<uint8_t> & p, size_t at, int v)
{
	p[at] = uint16_t(v) >> 8;
	p[at + 1] = uint16_t(v) & 0xff;
}

int16_t directed(int16_t level, uint16_t direction)
{
	double angle = direction * 2 * std::numbers::pi / 65536.;
	return int16_t(std::clamp<long>(std::lround(level * std::sin(angle)), -32768, 32767));
}

void put_envelope(std::vector<uint8_t> & p, size_t at, const wivrn::wheel_ff_envelope & e)
{
	p[at] = std::min(e.attack_level >> 7, 0xff);
	put16(p, at + 1, e.attack_length);
	p[at + 3] = std::min(e.fade_level >> 7, 0xff);
	put16(p, at + 4, e.fade_length);
}

// Saturation and deadband are sent as 15-bit values
void put15(std::vector<uint8_t> & p, size_t at, uint16_t v)
{
	p[at] = v >> 9;
	p[at + 1] = (v >> 1) & 0xff;
}

void put_condition(std::vector<uint8_t> & p, const wivrn::wheel_ff_effect::condition & c)
{
	put15(p, 6, c.left_saturation);
	put16(p, 8, c.left_coeff);
	put15(p, 10, c.deadband);
	put16(p, 12, c.center);
	put16(p, 14, c.right_coeff);
	put15(p, 16, c.right_saturation);
}
} // namespace

usb_layout parse_usb_configuration(std::span<const uint8_t> d)
{
	constexpr uint8_t type_configuration = 2;
	constexpr uint8_t type_interface = 4;
	constexpr uint8_t type_endpoint = 5;
	constexpr uint8_t type_hid = 0x21;
	constexpr uint8_t type_report = 0x22;
	constexpr uint8_t class_hid = 3;
	constexpr uint8_t class_vendor = 0xff;

	usb_layout res;
	std::optional<usb_layout::hid_interface> hid;
	std::optional<usb_layout::vendor_interface> vendor;
	uint8_t interface_class = 0;
	uint8_t interface_number = 0;
	bool configuration_seen = false;

	auto finish_interface = [&] {
		if (hid and hid->in.address and not res.hid)
			res.hid = hid;
		if (vendor and vendor->out.address and not res.vendor)
			res.vendor = vendor;
		hid.reset();
		vendor.reset();
	};

	for (size_t i = 0; i + 2 <= d.size();)
	{
		uint8_t length = d[i];
		uint8_t type = d[i + 1];
		if (length < 2 or i + length > d.size())
			break;
		auto desc = d.subspan(i, length);
		i += length;

		switch (type)
		{
			case type_configuration:
				// Only the first (active) configuration
				if (configuration_seen)
					i = d.size();
				configuration_seen = true;
				break;
			case type_interface:
				if (length < 9)
					break;
				finish_interface();
				interface_number = desc[2];
				interface_class = desc[5];
				if (interface_class == class_hid)
					hid = usb_layout::hid_interface{.number = interface_number};
				else if (interface_class == class_vendor and desc[3] == 0 /* alternate setting */)
					vendor = usb_layout::vendor_interface{.number = interface_number};
				break;
			case type_hid:
				// bNumDescriptors at 5, then (bDescriptorType, wDescriptorLength) pairs
				if (hid and length >= 9)
					for (size_t n = 0; n < desc[5] and 6 + 3 * n + 2 < length; ++n)
						if (desc[6 + 3 * n] == type_report)
							hid->report_descriptor_length = desc[7 + 3 * n] | (desc[8 + 3 * n] << 8);
				break;
			case type_endpoint: {
				if (length < 7)
					break;
				uint8_t address = desc[2];
				uint8_t transfer = desc[3] & 3; // 2: bulk, 3: interrupt
				usb_layout::endpoint ep{.address = address, .max_packet = uint16_t((desc[4] | (desc[5] << 8)) & 0x7ff)};
				bool in = address & 0x80;
				if (hid and transfer == 3)
				{
					if (in and not hid->in.address)
						hid->in = ep;
					else if (not in and not hid->out)
						hid->out = ep;
				}
				if (vendor and not in and (transfer == 2 or transfer == 3) and not vendor->out.address)
					vendor->out = ep;
				break;
			}
		}
	}
	finish_interface();
	if (res.hid and res.hid->report_descriptor_length == 0)
		res.hid.reset();
	return res;
}

std::vector<wivrn::from_headset::wheel_added::axis> input_layout::axes() const
{
	std::vector<wivrn::from_headset::wheel_added::axis> res;
	for (const auto & f: fields)
	{
		switch (f.type)
		{
			case input_field::kind::axis:
				res.push_back({.code = f.code, .min = f.logical_min, .max = f.logical_max, .fuzz = 0, .flat = 0});
				break;
			case input_field::kind::hat:
				res.push_back({.code = ABS_HAT0X, .min = -1, .max = 1, .fuzz = 0, .flat = 0});
				res.push_back({.code = ABS_HAT0Y, .min = -1, .max = 1, .fuzz = 0, .flat = 0});
				break;
			case input_field::kind::button:
				break;
		}
	}
	return res;
}

std::vector<uint16_t> input_layout::keys() const
{
	std::vector<uint16_t> res;
	for (const auto & f: fields)
		if (f.type == input_field::kind::button)
			res.push_back(f.code);
	return res;
}

std::optional<input_layout> parse_report_descriptor(std::span<const uint8_t> d)
{
	input_layout layout;
	globals g;
	std::vector<globals> stack;
	std::vector<uint32_t> usages; // (page << 16) | usage
	std::optional<uint32_t> usage_min;
	std::optional<uint32_t> usage_max;
	uint16_t application = 0;
	int collection_depth = 0;
	std::map<uint8_t, uint32_t> bit_offsets; // per report id
	std::set<uint16_t> abs_used;
	std::set<uint16_t> keys_used;

	auto full_usage = [&](uint32_t value, size_t size) {
		return size == 4 ? value : (uint32_t(g.usage_page) << 16) | value;
	};

	size_t i = 0;
	while (i < d.size())
	{
		uint8_t prefix = d[i++];
		if (prefix == 0xfe) // long item: size, tag, data
		{
			if (i + 2 > d.size())
				return std::nullopt;
			i += 2 + d[i];
			continue;
		}
		size_t size = (prefix & 3) == 3 ? 4 : (prefix & 3);
		if (i + size > d.size())
			return std::nullopt;
		uint32_t value = 0;
		for (size_t b = 0; b < size; ++b)
			value |= uint32_t(d[i + b]) << (8 * b);
		int32_t svalue = size ? sign_extend(value, 8 * size) : 0;
		i += size;

		uint8_t type = (prefix >> 2) & 3;
		uint8_t tag = prefix >> 4;

		if (type == 1) // global
		{
			switch (tag)
			{
				case 0x0:
					g.usage_page = value;
					break;
				case 0x1:
					g.logical_min = svalue;
					break;
				case 0x2:
					g.logical_max = svalue;
					break;
				case 0x7:
					g.report_size = value;
					break;
				case 0x8:
					if (value == 0 or value > 0xff)
						return std::nullopt;
					g.report_id = value;
					layout.report_ids = true;
					break;
				case 0x9:
					g.report_count = value;
					break;
				case 0xa:
					stack.push_back(g);
					break;
				case 0xb:
					if (stack.empty())
						return std::nullopt;
					g = stack.back();
					stack.pop_back();
					break;
			}
			continue;
		}

		if (type == 2) // local
		{
			switch (tag)
			{
				case 0x0:
					usages.push_back(full_usage(value, size));
					break;
				case 0x1:
					usage_min = full_usage(value, size);
					break;
				case 0x2:
					usage_max = full_usage(value, size);
					break;
			}
			continue;
		}

		if (type != 0) // reserved
			continue;

		// main item
		switch (tag)
		{
			case 0xa: // collection
				if (collection_depth++ == 0 and value == 1 /* application */ and not usages.empty())
					application = (usages[0] >> 16) == page_generic_desktop ? usages[0] & 0xffff : 0;
				break;
			case 0xc: // end collection
				if (--collection_depth < 0)
					return std::nullopt;
				break;
			case 0x8: // input
			{
				if (g.report_size == 0 or g.report_size > 32 or g.report_count > 1024)
					return std::nullopt;

				uint32_t & offset = bit_offsets[g.report_id];
				bool constant = value & 1;
				bool variable = value & 2;

				std::vector<uint32_t> field_usages = usages;
				if (usage_min and usage_max and *usage_max >= *usage_min and *usage_max - *usage_min < 1024)
					for (uint32_t u = *usage_min; u <= *usage_max; ++u)
						field_usages.push_back(u);

				// Logical maximum is sometimes written unsigned without room for a sign bit
				int32_t lmin = g.logical_min;
				int32_t lmax = g.logical_max;
				if (lmax < lmin and lmin >= 0)
					lmax = int32_t(uint32_t(lmax) & ((1ull << g.report_size) - 1));

				for (uint32_t n = 0; n < g.report_count; ++n, offset += g.report_size)
				{
					if (constant or not variable or field_usages.empty())
						continue;
					uint32_t u = field_usages[std::min<size_t>(n, field_usages.size() - 1)];
					uint16_t page = u >> 16;
					uint16_t usage = u & 0xffff;

					input_field f{
					        .report_id = g.report_id,
					        .bit_offset = offset,
					        .bit_size = g.report_size,
					        .logical_min = lmin,
					        .logical_max = lmax,
					};

					if (page == page_generic_desktop and usage == usage_hat_switch)
					{
						if (abs_used.contains(ABS_HAT0X))
							continue;
						abs_used.insert(ABS_HAT0X);
						f.type = input_field::kind::hat;
						f.code = ABS_HAT0X;
					}
					else if (page == page_button)
					{
						int code = button_code(application, usage);
						if (code < 0 or not keys_used.insert(code).second)
							continue;
						f.type = input_field::kind::button;
						f.code = code;
					}
					else if (int code = abs_code(page, usage); code >= 0)
					{
						// Like hid-input, a usage seen twice takes the next free code
						while (code < ABS_HAT0X and abs_used.contains(code))
							++code;
						if (code >= ABS_HAT0X)
							continue;
						abs_used.insert(code);
						f.type = input_field::kind::axis;
						f.code = code;
					}
					else
						continue;

					layout.fields.push_back(f);
				}
				break;
			}
			case 0x9: // output
			case 0xb: // feature
				break;
		}
		// local items apply to the next main item only
		usages.clear();
		usage_min.reset();
		usage_max.reset();
	}

	if (layout.fields.empty())
		return std::nullopt;
	return layout;
}

input_state initial_state(const input_layout & layout)
{
	return {
	        .axes = std::vector<int32_t>(layout.axes().size()),
	        .keys = std::vector<uint8_t>((layout.keys().size() + 7) / 8),
	};
}

bool decode_report(const input_layout & layout, std::span<const uint8_t> report, input_state & state)
{
	uint8_t id = 0;
	if (layout.report_ids)
	{
		if (report.empty())
			return false;
		id = report[0];
		report = report.subspan(1);
	}

	bool matched = false;
	size_t axis = 0;
	size_t key = 0;
	for (const auto & f: layout.fields)
	{
		bool here = f.report_id == id and f.bit_offset + f.bit_size <= report.size() * 8;
		matched |= here;

		uint32_t raw = here ? extract(report, f.bit_offset, f.bit_size) : 0;
		int32_t value = f.logical_min < 0 ? sign_extend(raw, f.bit_size) : int32_t(raw);

		switch (f.type)
		{
			case input_field::kind::axis:
				if (here)
					state.axes[axis] = value;
				++axis;
				break;
			case input_field::kind::hat:
				if (here)
				{
					// 0 is up, then clockwise; out of range is centered
					static const int8_t hat_x[] = {0, 1, 1, 1, 0, -1, -1, -1};
					static const int8_t hat_y[] = {-1, -1, 0, 1, 1, 1, 0, -1};
					int64_t pos = int64_t(value) - f.logical_min;
					int64_t positions = int64_t(f.logical_max) - f.logical_min + 1;
					if (positions == 4)
						pos *= 2; // 4-way hat
					bool centered = pos < 0 or pos > 7 or value > f.logical_max;
					state.axes[axis] = centered ? 0 : hat_x[pos];
					state.axes[axis + 1] = centered ? 0 : hat_y[pos];
				}
				axis += 2;
				break;
			case input_field::kind::button:
				if (here)
				{
					uint8_t bit = 1 << (key % 8);
					if (value)
						state.keys[key / 8] |= bit;
					else
						state.keys[key / 8] &= ~bit;
				}
				++key;
				break;
		}
	}
	return matched;
}

wivrn::from_headset::wheel_state diff(uint8_t id, const input_layout & layout, const input_state & before, const input_state & after)
{
	wivrn::from_headset::wheel_state res{.id = id, .keys = after.keys};
	auto axes = layout.axes();
	for (size_t i = 0; i < axes.size() and i < after.axes.size(); ++i)
		if (i >= before.axes.size() or before.axes[i] != after.axes[i])
			res.axes.push_back({.code = axes[i].code, .value = after.axes[i]});
	return res;
}

namespace hidpp
{
std::vector<uint8_t> request(uint8_t feature_index, uint8_t function, std::span<const uint8_t> params)
{
	// Long reports carry 16 parameters; longer requests (periodic and condition
	// effects) go in a very long report
	bool very_long = params.size() > long_length - 4;
	std::vector<uint8_t> msg(very_long ? very_long_length : long_length);
	msg[0] = very_long ? report_very_long : report_long;
	msg[1] = device_index;
	msg[2] = feature_index;
	msg[3] = (function << 4) | software_id;
	std::copy_n(params.begin(), std::min(params.size(), msg.size() - 4), msg.begin() + 4);
	return msg;
}

std::vector<uint8_t> get_feature(uint16_t feature)
{
	uint8_t params[] = {uint8_t(feature >> 8), uint8_t(feature & 0xff)};
	return request(0 /* IRoot */, 0 /* getFeature */, params);
}

std::optional<reply> parse_reply(std::span<const uint8_t> r)
{
	if (r.size() < 7)
		return std::nullopt;
	if (r[0] != report_short and r[0] != report_long and r[0] != report_very_long)
		return std::nullopt;
	if (r[1] != device_index)
		return std::nullopt;

	reply res{};
	size_t params_at;
	if (r[2] == error_feature)
	{
		res.error = true;
		res.feature_index = r[3];
		res.function = r[4] >> 4;
		if ((r[4] & 0xf) != software_id)
			return std::nullopt;
		res.error_code = r[5];
		params_at = 5;
	}
	else
	{
		res.feature_index = r[2];
		res.function = r[3] >> 4;
		if ((r[3] & 0xf) != software_id)
			return std::nullopt;
		params_at = 4;
	}
	std::copy_n(r.begin() + params_at, std::min(r.size() - params_at, res.params.size()), res.params.begin());
	return res;
}

namespace ff
{
std::optional<std::vector<uint8_t>> download_params(uint8_t slot, const wivrn::wheel_ff_effect & e)
{
	std::vector<uint8_t> p;
	auto common = [&](size_t size, uint8_t type) {
		p.assign(size, 0);
		p[0] = slot;
		p[1] = type;
		put16(p, 2, e.replay_length);
		put16(p, 4, e.replay_delay);
	};

	switch (e.type)
	{
		case FF_CONSTANT: {
			auto c = std::get_if<wivrn::wheel_ff_effect::constant>(&e.u);
			if (not c)
				return std::nullopt;
			common(14, type_constant);
			put16(p, 6, directed(c->level, e.direction));
			put_envelope(p, 8, c->envelope);
			return p;
		}
		case FF_RAMP: {
			auto r = std::get_if<wivrn::wheel_ff_effect::ramp>(&e.u);
			if (not r)
				return std::nullopt;
			common(16, type_ramp);
			put16(p, 6, directed(r->start_level, e.direction));
			put16(p, 8, directed(r->end_level, e.direction));
			put_envelope(p, 10, r->envelope);
			return p;
		}
		case FF_PERIODIC: {
			auto w = std::get_if<wivrn::wheel_ff_effect::periodic>(&e.u);
			if (not w)
				return std::nullopt;
			uint8_t type;
			switch (w->waveform)
			{
				case FF_SINE:
					type = type_sine;
					break;
				case FF_SQUARE:
					type = type_square;
					break;
				case FF_TRIANGLE:
					type = type_triangle;
					break;
				case FF_SAW_UP:
					type = type_sawtooth_up;
					break;
				case FF_SAW_DOWN:
					type = type_sawtooth_down;
					break;
				default: // FF_CUSTOM
					return std::nullopt;
			}
			common(20, type);
			put16(p, 6, directed(w->magnitude, e.direction));
			put16(p, 8, w->offset);
			put16(p, 10, w->period);
			put16(p, 12, w->phase);
			put_envelope(p, 14, w->envelope);
			return p;
		}
		case FF_SPRING:
		case FF_DAMPER:
		case FF_FRICTION:
		case FF_INERTIA: {
			auto c = std::get_if<std::array<wivrn::wheel_ff_effect::condition, 2>>(&e.u);
			if (not c)
				return std::nullopt;
			uint8_t type = e.type == FF_SPRING   ? type_spring
			               : e.type == FF_DAMPER ? type_damper
			               : e.type == FF_FRICTION
			                       ? type_friction
			                       : type_inertia;
			common(18, type);
			// The wheel has one axis: the first condition
			put_condition(p, (*c)[0]);
			return p;
		}
		default: // FF_RUMBLE and unknown types
			return std::nullopt;
	}
}

std::vector<uint8_t> autocenter_params(uint16_t magnitude)
{
	std::vector<uint8_t> p(18, 0);
	p[1] = type_spring | autostart;
	// replay length 0: until destroyed
	wivrn::wheel_ff_effect::condition c{
	        .right_saturation = magnitude,
	        .left_saturation = magnitude,
	        .right_coeff = int16_t(magnitude >> 3),
	        .left_coeff = int16_t(magnitude >> 3),
	        .deadband = 0,
	        .center = 0,
	};
	put_condition(p, c);
	return p;
}

std::vector<uint8_t> gain_params(uint16_t gain)
{
	// global gain, then boost (left at 0)
	return {uint8_t(gain >> 8), uint8_t(gain & 0xff), 0, 0};
}

std::vector<uint16_t> supported_effects()
{
	return {FF_CONSTANT, FF_PERIODIC, FF_SQUARE, FF_TRIANGLE, FF_SINE, FF_SAW_UP, FF_SAW_DOWN, FF_RAMP, FF_SPRING, FF_DAMPER, FF_FRICTION, FF_INERTIA, FF_GAIN, FF_AUTOCENTER};
}
} // namespace ff
} // namespace hidpp

std::string describe(const wivrn::to_headset::wheel_ff & ff)
{
	using op = wivrn::to_headset::wheel_ff::operation;
	const char * name = "?";
	switch (ff.op)
	{
		case op::upload:
			name = "upload";
			break;
		case op::erase:
			name = "erase";
			break;
		case op::play:
			name = "play";
			break;
		case op::stop:
			name = "stop";
			break;
		case op::gain:
			name = "gain";
			break;
		case op::autocenter:
			name = "autocenter";
			break;
	}
	std::string res = std::format("wheel {} ff {} effect={} value={}", ff.id, name, ff.effect_id, ff.value);
	if (ff.effect)
	{
		const auto & e = *ff.effect;
		res += std::format(" type=0x{:02x} dir=0x{:04x} len={} delay={}", e.type, e.direction, e.replay_length, e.replay_delay);
		if (auto c = std::get_if<wivrn::wheel_ff_effect::constant>(&e.u))
			res += std::format(" level={}", c->level);
		else if (auto r = std::get_if<wivrn::wheel_ff_effect::ramp>(&e.u))
			res += std::format(" start={} end={}", r->start_level, r->end_level);
		else if (auto w = std::get_if<wivrn::wheel_ff_effect::periodic>(&e.u))
			res += std::format(" wave=0x{:02x} period={} mag={} offset={}", w->waveform, w->period, w->magnitude, w->offset);
		else if (auto k = std::get_if<std::array<wivrn::wheel_ff_effect::condition, 2>>(&e.u))
			res += std::format(" coeff={}/{} sat={}/{} center={} deadband={}",
			                   (*k)[0].left_coeff,
			                   (*k)[0].right_coeff,
			                   (*k)[0].left_saturation,
			                   (*k)[0].right_saturation,
			                   (*k)[0].center,
			                   (*k)[0].deadband);
	}
	return res;
}

} // namespace wheel
