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

#include "usb_wheel.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <format>
#include <linux/usbdevice_fs.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>

namespace wheel
{

namespace
{
constexpr unsigned transfer_timeout_ms = 100;
constexpr auto reply_timeout = std::chrono::milliseconds(250);
// Effects the server may define at once (it caps ff_effects_max at 64)
constexpr size_t max_known_effects = 64;

std::vector<uint8_t> read_descriptors(int fd)
{
	std::vector<uint8_t> buf(4096);
	if (lseek(fd, 0, SEEK_SET) < 0)
		throw std::runtime_error(std::string("usbfs seek: ") + strerror(errno));
	ssize_t n = read(fd, buf.data(), buf.size());
	if (n < 18)
		throw std::runtime_error("usbfs: no device descriptor");
	buf.resize(n);
	return buf;
}

// Detaches the kernel driver (Android binds usbhid to the wheel) and claims the interface
void claim_interface(int fd, uint8_t number)
{
	usbdevfs_disconnect_claim dc{};
	dc.interface = number;
	if (ioctl(fd, USBDEVFS_DISCONNECT_CLAIM, &dc) == 0)
		return;

	// Older kernels: disconnect then claim
	usbdevfs_ioctl disconnect{.ifno = int(number), .ioctl_code = USBDEVFS_DISCONNECT, .data = nullptr};
	if (ioctl(fd, USBDEVFS_IOCTL, &disconnect) < 0 and errno != ENODATA)
		spdlog::warn("wheel: detaching kernel driver from interface {}: {}", number, strerror(errno));
	unsigned int n = number;
	if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &n) < 0)
		throw std::runtime_error(std::string("claiming interface: ") + strerror(errno));
}

int bulk(int fd, uint8_t endpoint, void * data, size_t size, unsigned timeout_ms)
{
	usbdevfs_bulktransfer t{.ep = endpoint, .len = unsigned(size), .timeout = timeout_ms, .data = data};
	return ioctl(fd, USBDEVFS_BULK, &t);
}
} // namespace

bool mode_switch(int fd)
{
	try
	{
		auto desc = read_descriptors(fd);
		auto usb = parse_usb_configuration(std::span(desc).subspan(18));
		if (not usb.vendor)
		{
			spdlog::warn("wheel: Xbox-mode G920 has no vendor OUT endpoint");
			return false;
		}
		claim_interface(fd, usb.vendor->number);
		auto msg = g920_mode_switch_message;
		int n = bulk(fd, usb.vendor->out.address, msg.data(), msg.size(), 1000);
		if (n != int(msg.size()))
		{
			spdlog::warn("wheel: mode switch transfer failed: {}", n < 0 ? strerror(errno) : "short write");
			return false;
		}
		spdlog::info("wheel: G920 switched to HID mode, waiting for it to reconnect");
		unsigned int number = usb.vendor->number;
		ioctl(fd, USBDEVFS_RELEASEINTERFACE, &number);
		return true;
	}
	catch (std::exception & e)
	{
		spdlog::warn("wheel: mode switch: {}", e.what());
		return false;
	}
}

usb_wheel::usb_wheel(int fd, uint8_t id, uint16_t vendor, uint16_t product, std::string name, sink send_) :
        fd(fd), id(id), send(std::move(send_))
{
	auto desc = read_descriptors(fd);
	uint16_t version = desc[12] | (desc[13] << 8); // bcdDevice
	usb = parse_usb_configuration(std::span(desc).subspan(18));
	if (not usb.hid)
		throw std::runtime_error("no HID interface with an interrupt IN endpoint");

	claim();
	try
	{
		auto report_descriptor = read_report_descriptor();
		auto parsed = parse_report_descriptor(report_descriptor);
		if (not parsed)
			throw std::runtime_error("unusable HID report descriptor");
		layout = std::move(*parsed);
		read_input_reports();

		reader = std::thread([this] { read_loop(); });
		init_ff();
	}
	catch (...)
	{
		quit = true;
		if (reader.joinable())
			reader.join();
		release();
		throw;
	}

	added = {
	        .id = id,
	        .vendor = vendor,
	        .product = product,
	        .version = version,
	        .name = std::move(name),
	        .axes = layout.axes(),
	        .keys = layout.keys(),
	};
	if (ff_index)
	{
		added.ff = hidpp::ff::supported_effects(version);
		added.ff_effects_max = ff_effects_max;
	}

	ff_thread = std::thread([this] { ff_loop(); });

	spdlog::info("wheel {}: {} ({:04x}:{:04x}), {} axes, {} buttons, force feedback {}",
	             id,
	             added.name,
	             vendor,
	             product,
	             added.axes.size(),
	             added.keys.size(),
	             ff_index ? "on" : "off");
	send(wivrn::from_headset::wheel_added{added});
	announced = true;
}

usb_wheel::~usb_wheel()
{
	{
		// Under the lock, or ff_loop may miss the wakeup between its check and its wait
		std::lock_guard lock(ff_mutex);
		quit = true;
	}
	ff_cv.notify_all();
	if (ff_thread.joinable())
		ff_thread.join();

	// Leave the wheel without running effects
	if (ff_index and not disconnected)
		write(hidpp::request(*ff_index, hidpp::ff::reset_all, {}));

	if (reader.joinable())
		reader.join();
	release();
}

void usb_wheel::claim()
{
	claim_interface(fd, usb.hid->number);
}

void usb_wheel::release()
{
	unsigned int number = usb.hid->number;
	ioctl(fd, USBDEVFS_RELEASEINTERFACE, &number);
	// Give the interface back to the system's driver
	usbdevfs_ioctl connect{.ifno = int(number), .ioctl_code = USBDEVFS_CONNECT, .data = nullptr};
	ioctl(fd, USBDEVFS_IOCTL, &connect);
}

std::vector<uint8_t> usb_wheel::read_report_descriptor()
{
	std::vector<uint8_t> buf(usb.hid->report_descriptor_length);
	usbdevfs_ctrltransfer t{
	        .bRequestType = 0x81, // device to host, standard, interface
	        .bRequest = 0x06,     // GET_DESCRIPTOR
	        .wValue = 0x2200,     // report descriptor
	        .wIndex = usb.hid->number,
	        .wLength = uint16_t(buf.size()),
	        .timeout = 1000,
	        .data = buf.data(),
	};
	int n = ioctl(fd, USBDEVFS_CONTROL, &t);
	if (n < 0)
		throw std::runtime_error(std::string("reading report descriptor: ") + strerror(errno));
	buf.resize(n);
	return buf;
}

void usb_wheel::read_input_reports()
{
	// Like usbhid at init: ask for each input report's current value (GET_REPORT). A
	// device may refuse; its first interrupt report then gives the state.
	std::map<uint8_t, uint32_t> bits; // report id -> bits used
	for (const auto & f: layout.fields)
		bits[f.report_id] = std::max(bits[f.report_id], f.bit_offset + f.bit_size);

	input_state state = initial_state(layout);
	bool any = false;
	for (auto [report_id, size]: bits)
	{
		std::vector<uint8_t> buf((layout.report_ids ? 1 : 0) + (size + 7) / 8);
		usbdevfs_ctrltransfer t{
		        .bRequestType = 0xa1,                   // device to host, class, interface
		        .bRequest = 0x01,                       // GET_REPORT
		        .wValue = uint16_t(0x0100 | report_id), // input report, id
		        .wIndex = usb.hid->number,
		        .wLength = uint16_t(buf.size()),
		        .timeout = 250,
		        .data = buf.data(),
		};
		int n = ioctl(fd, USBDEVFS_CONTROL, &t);
		if (n != int(buf.size()))
		{
			// Refused, or short: a partial report would invent the missing fields
			spdlog::debug("wheel {}: GET_REPORT {} unusable: {}", id, report_id, n < 0 ? strerror(errno) : "short");
			continue;
		}
		any |= decode_report(layout, std::span(buf).first(n), state);
	}
	if (any)
		seed = state;
}

bool usb_wheel::write(std::span<const uint8_t> report)
{
	std::vector<uint8_t> data(report.begin(), report.end());
	int n;
	if (usb.hid->out)
		n = bulk(fd, usb.hid->out->address, data.data(), data.size(), transfer_timeout_ms);
	else
	{
		usbdevfs_ctrltransfer t{
		        .bRequestType = 0x21,                 // host to device, class, interface
		        .bRequest = 0x09,                     // SET_REPORT
		        .wValue = uint16_t(0x0200 | data[0]), // output report, id
		        .wIndex = usb.hid->number,
		        .wLength = uint16_t(data.size()),
		        .timeout = transfer_timeout_ms,
		        .data = data.data(),
		};
		n = ioctl(fd, USBDEVFS_CONTROL, &t);
	}
	if (n != int(data.size()))
	{
		spdlog::warn("wheel {}: HID++ write failed: {}", id, n < 0 ? strerror(errno) : "short write");
		return false;
	}
	return true;
}

std::optional<hidpp::reply> usb_wheel::call(uint8_t feature_index, uint8_t function, std::span<const uint8_t> params)
{
	std::unique_lock lock(reply_mutex);
	last_reply.reset();
	lock.unlock();

	if (not write(hidpp::request(feature_index, function, params)))
		return std::nullopt;

	lock.lock();
	if (not reply_cv.wait_for(lock, reply_timeout, [&] {
		    return quit or (last_reply and last_reply->feature_index == feature_index and last_reply->function == function);
	    }) or
	    not last_reply)
	{
		spdlog::warn("wheel {}: no HID++ reply to feature {} function {}", id, feature_index, function);
		return std::nullopt;
	}
	auto r = *last_reply;
	if (r.error)
		spdlog::warn("wheel {}: HID++ error {} from feature {} function {}", id, r.error_code, feature_index, function);
	return r;
}

void usb_wheel::init_ff()
{
	auto feature = call(0, 0, std::array<uint8_t, 2>{hidpp::force_feedback_feature >> 8, hidpp::force_feedback_feature & 0xff});
	if (not feature or feature->error or feature->params[0] == 0)
	{
		spdlog::warn("wheel: no HID++ force feedback feature, wheel without force feedback");
		return;
	}
	uint8_t index = feature->params[0];

	auto info = call(index, hidpp::ff::get_info, {});
	if (not info or info->error or info->params[0] < 2)
	{
		spdlog::warn("wheel: force feedback info unavailable, wheel without force feedback");
		return;
	}
	// One slot stays free for the autocenter spring
	ff_effects_max = std::min(info->params[0] - 1, 64); // the server takes at most 64

	if (auto r = call(index, hidpp::ff::reset_all, {}); not r or r->error)
		return;
	ff_index = index;
}

void usb_wheel::ff(const wivrn::to_headset::wheel_ff & request)
{
	using op = wivrn::to_headset::wheel_ff::operation;
	std::lock_guard lock(ff_mutex);

	// Requests are folded into what the wheel should end up with, not queued: a game
	// sending faster than the wheel answers then costs nothing, and a stop is never lost.
	switch (request.op)
	{
		case op::gain:
			pending_gain = request.value;
			break;
		case op::autocenter:
			pending_autocenter = request.value;
			break;
		case op::upload:
			if (not request.effect)
				return;
			// Bounded by the effects the server may have (64); ids beyond that are junk
			if (not known_effects.contains(request.effect_id) and known_effects.size() >= max_known_effects)
			{
				if (dropped_ff++ % 1000 == 0)
					spdlog::warn("wheel {}: too many force feedback effects, dropping upload ({} dropped)", id, dropped_ff);
				return;
			}
			known_effects.insert(request.effect_id);
			pending[request.effect_id].upload = request.effect;
			break;
		case op::play:
		case op::stop:
			// An effect never uploaded has nothing to play or stop
			if (not known_effects.contains(request.effect_id))
				return;
			pending[request.effect_id].play = request.op == op::play ? std::optional(request.value) : std::optional(0);
			break;
		case op::erase:
			if (not known_effects.contains(request.effect_id))
				return;
			known_effects.erase(request.effect_id);
			// Whatever was pending for the old effect no longer matters
			pending[request.effect_id] = {.erase = true};
			break;
	}
	ff_cv.notify_one();
}

void usb_wheel::ff_loop()
{
	using wivrn::to_headset::wheel_ff;
	using op = wheel_ff::operation;
	while (true)
	{
		std::map<int16_t, pending_effect> effects;
		std::optional<int32_t> gain;
		std::optional<int32_t> autocenter;
		{
			std::unique_lock lock(ff_mutex);
			ff_cv.wait(lock, [&] { return quit or not pending.empty() or pending_gain or pending_autocenter; });
			if (quit)
				return;
			effects = std::exchange(pending, {});
			gain = std::exchange(pending_gain, std::nullopt);
			autocenter = std::exchange(pending_autocenter, std::nullopt);
		}

		for (auto & [effect_id, p]: effects)
		{
			// Erase first (it came before anything else still pending for this id), then
			// the latest definition, then the latest play/stop
			if (p.erase)
				apply({.id = id, .op = op::erase, .effect_id = effect_id});
			if (p.upload)
				apply({.id = id, .op = op::upload, .effect_id = effect_id, .effect = std::move(p.upload)});
			if (p.play)
				apply({.id = id, .op = *p.play > 0 ? op::play : op::stop, .effect_id = effect_id, .value = *p.play});
		}
		if (gain)
			apply({.id = id, .op = op::gain, .value = *gain});
		if (autocenter)
			apply({.id = id, .op = op::autocenter, .value = *autocenter});
	}
}

void usb_wheel::apply(const wivrn::to_headset::wheel_ff & request)
{
	using op = wivrn::to_headset::wheel_ff::operation;
	namespace ff = hidpp::ff;

	std::string result;
	auto slot = [&]() -> std::optional<uint8_t> {
		auto it = slots.find(request.effect_id);
		if (it == slots.end())
			return std::nullopt;
		return it->second;
	}();

	if (not ff_index)
		result = "no force feedback";
	else
	{
		switch (request.op)
		{
			case op::upload: {
				if (not request.effect)
				{
					result = "no effect";
					break;
				}
				auto params = ff::download_params(slot.value_or(0), *request.effect);
				if (not params)
				{
					result = "unsupported effect";
					break;
				}
				auto r = call(*ff_index, ff::download_effect, *params);
				if (r and not r->error and r->params[0])
				{
					slots[request.effect_id] = r->params[0];
					result = std::format("slot {}", r->params[0]);
				}
				else
					result = "failed";
				break;
			}
			case op::erase:
				if (slot)
				{
					call(*ff_index, ff::destroy_effect, std::array<uint8_t, 1>{*slot});
					slots.erase(request.effect_id);
					result = std::format("slot {}", *slot);
				}
				else
					result = "unknown effect";
				break;
			case op::play:
			case op::stop:
				if (slot)
				{
					uint8_t state = request.op == op::play and request.value > 0 ? ff::state_play : ff::state_stop;
					auto r = call(*ff_index, ff::set_effect_state, std::array<uint8_t, 2>{*slot, state});
					result = r and not r->error ? std::format("slot {}", *slot) : "failed";
				}
				else
					result = "unknown effect";
				break;
			case op::gain: {
				auto r = call(*ff_index, ff::set_global_gains, ff::gain_params(std::clamp(request.value, 0, 0xffff)));
				result = r and not r->error ? "ok" : "failed";
				break;
			}
			case op::autocenter:
				if (autocenter_slot)
				{
					call(*ff_index, ff::destroy_effect, std::array<uint8_t, 1>{*autocenter_slot});
					autocenter_slot.reset();
				}
				if (request.value > 0)
				{
					auto r = call(*ff_index, ff::download_effect, ff::autocenter_params(std::clamp(request.value, 0, 0xffff)));
					if (r and not r->error and r->params[0])
						autocenter_slot = r->params[0];
				}
				result = autocenter_slot ? std::format("slot {}", *autocenter_slot) : "off";
				break;
		}
	}

	if (log_ff)
		spdlog::info("{} -> {}", describe(request), result);
}

void usb_wheel::read_loop()
{
	std::vector<uint8_t> buf(std::max<size_t>(usb.hid->in.max_packet, hidpp::very_long_length));
	// No state goes out until the device has told us one: zeros would be full left lock
	bool have_state = seed.has_value();
	input_state state = seed.value_or(initial_state(layout));
	input_state sent = state;
	bool sent_once = false;
	int errors = 0;

	while (not quit)
	{
		int n = bulk(fd, usb.hid->in.address, buf.data(), buf.size(), transfer_timeout_ms);
		if (n < 0)
		{
			if (errno == ETIMEDOUT or errno == EINTR)
				n = 0;
			else if (errno == ENODEV or errno == ESHUTDOWN or ++errors > 50)
			{
				spdlog::info("wheel {}: device gone ({})", id, strerror(errno));
				disconnected = true;
				reply_cv.notify_all();
				return;
			}
			else
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}
		}
		else
			errors = 0;

		auto report = std::span(buf).first(n);
		if (n > 0)
		{
			if (auto r = hidpp::parse_reply(report))
			{
				std::lock_guard lock(reply_mutex);
				last_reply = *r;
				reply_cv.notify_all();
				continue;
			}
			have_state |= decode_report(layout, report, state);
		}

		// Nothing goes out before wheel_added; the first state after it is complete
		if (announced and have_state and (not sent_once or state != sent))
		{
			auto packet = sent_once ? diff(id, layout, sent, state) : diff(id, layout, {}, state);
			send(std::move(packet));
			sent = state;
			sent_once = true;
		}
	}
}

} // namespace wheel
