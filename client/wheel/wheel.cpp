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

#include "wheel.h"

#include <spdlog/spdlog.h>

namespace wheel
{

namespace
{
// The server takes at most 4 wheels
constexpr size_t max_wheels = 4;

bool is_g920(uint16_t vendor, uint16_t product)
{
	return vendor == logitech_vendor and (product == g920_xbox_product or product == g920_hid_product);
}
} // namespace

manager & manager::instance()
{
	static manager m;
	return m;
}

void manager::set_platform(platform p)
{
	std::lock_guard lock(mutex);
	plat = std::move(p);
}

void manager::attached(std::string path, uint16_t vendor, uint16_t product, std::string name, bool permission)
{
	if (not is_g920(vendor, product))
		return;
	std::lock_guard lock(mutex);
	events.push_back({.attached = true, .path = std::move(path), .dev = {.vendor = vendor, .product = product, .name = std::move(name), .permission = permission}});
}

void manager::detached(std::string path)
{
	std::lock_guard lock(mutex);
	events.push_back({.attached = false, .path = std::move(path)});
}

void manager::handle(const std::string & path, device & dev)
{
	if (not enabled)
		return;

	if (not dev.permission)
	{
		// One prompt per plug: a refusal is not asked again until the wheel is replugged
		if (not dev.permission_requested and plat.request_permission)
		{
			spdlog::info("wheel: asking for access to {} ({:04x}:{:04x})", dev.name, dev.vendor, dev.product);
			dev.permission_requested = true;
			plat.request_permission(path);
		}
		return;
	}

	if (dev.product == g920_xbox_product)
	{
		if (dev.mode_switched or not plat.open)
			return;
		dev.mode_switched = true;
		int fd = plat.open(path);
		if (fd < 0)
		{
			spdlog::warn("wheel: cannot open {}", path);
			return;
		}
		mode_switch(fd);
		plat.close(path);
		return;
	}

	if (sink and not wheels.contains(path))
		open_wheel(path, dev);
}

void manager::open_wheel(const std::string & path, const device & dev)
{
	if (wheels.size() >= max_wheels or not plat.open)
		return;

	auto taken = [&](uint8_t id) {
		for (auto & [_, w]: wheels)
			if (w->description().id == id)
				return true;
		return false;
	};
	uint8_t id = 0;
	while (taken(id))
		++id;

	int fd = plat.open(path);
	if (fd < 0)
	{
		spdlog::warn("wheel: cannot open {}", path);
		return;
	}
	try
	{
		wheels.emplace(path, std::make_unique<usb_wheel>(fd, id, dev.vendor, dev.product, dev.name, *sink));
	}
	catch (std::exception & e)
	{
		spdlog::warn("wheel: cannot use {}: {}", dev.name, e.what());
		plat.close(path);
	}
}

void manager::close_wheel(const std::string & path, bool send_removed)
{
	auto it = wheels.find(path);
	if (it == wheels.end())
		return;
	uint8_t id = it->second->description().id;
	wheels.erase(it); // joins its threads and releases the interface
	if (plat.close)
		plat.close(path);
	if (send_removed and sink)
		(*sink)(wivrn::from_headset::wheel_removed{.id = id});
	spdlog::info("wheel {}: released", id);
}

void manager::poll(bool enabled_)
{
	std::lock_guard lock(mutex);

	if (enabled != enabled_)
	{
		enabled = enabled_;
		if (enabled)
			for (auto & [path, dev]: devices)
				handle(path, dev);
		else
			while (not wheels.empty())
				close_wheel(wheels.begin()->first, true);
	}

	for (auto & e: std::exchange(events, {}))
	{
		if (e.attached)
		{
			auto [it, inserted] = devices.try_emplace(e.path, e.dev);
			if (not inserted)
			{
				// Permission granted (or a duplicate attach): keep what was asked already
				it->second.permission |= e.dev.permission;
			}
			handle(it->first, it->second);
		}
		else
		{
			close_wheel(e.path, true);
			devices.erase(e.path);
		}
	}

	for (auto it = wheels.begin(); it != wheels.end();)
	{
		auto next = std::next(it);
		if (it->second->gone())
			close_wheel(it->first, true);
		it = next;
	}
}

void manager::start_stream(usb_wheel::sink send)
{
	std::lock_guard lock(mutex);
	sink = std::move(send);
	// wheel_added again for every connection: the server forgets wheels on disconnect
	for (auto & [path, dev]: devices)
		handle(path, dev);
}

void manager::stop_stream()
{
	std::lock_guard lock(mutex);
	while (not wheels.empty())
		close_wheel(wheels.begin()->first, false);
	sink.reset();
}

void manager::ff(const wivrn::to_headset::wheel_ff & request)
{
	std::lock_guard lock(mutex);
	for (auto & [_, w]: wheels)
	{
		if (w->description().id == request.id)
		{
			w->ff(request);
			return;
		}
	}
	if (log_ff)
		spdlog::info("{} -> no such wheel", describe(request));
}

std::vector<std::string> manager::connected()
{
	std::lock_guard lock(mutex);
	std::vector<std::string> res;
	for (auto & [_, w]: wheels)
		res.push_back(w->description().name);
	return res;
}

} // namespace wheel
