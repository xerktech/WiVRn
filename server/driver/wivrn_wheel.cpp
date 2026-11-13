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

#include "wivrn_wheel.h"

#include <algorithm>
#include <bitset>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>

#include <nlohmann/json.hpp>
#include <set>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace wivrn::wheel
{
namespace
{
using json = nlohmann::json;

constexpr uint16_t max_abs = ABS_MISC; // 0x28

bool allowed_key(uint16_t code)
{
	// Mouse buttons and digitizer tools would make the device a pointer or tablet to libinput
	if ((code >= BTN_MOUSE and code <= BTN_TASK) or (code >= BTN_DIGI and code <= 0x14f))
		return false;
	return (code >= BTN_MISC and code <= BTN_GEAR_UP) or (code >= BTN_TRIGGER_HAPPY1 and code <= BTN_TRIGGER_HAPPY40);
}

bool is_effect_type(uint16_t code)
{
	return code >= FF_EFFECT_MIN and code <= FF_EFFECT_MAX;
}

bool allowed_ff(uint16_t code)
{
	// Waveforms are listed as ff bits too: the kernel checks a periodic effect's waveform
	// against them. FF_CUSTOM needs a data buffer that is not forwarded.
	return is_effect_type(code) or (code >= FF_WAVEFORM_MIN and code < FF_CUSTOM) or code == FF_GAIN or code == FF_AUTOCENTER;
}

wheel_ff_envelope envelope(const ff_envelope & e)
{
	return {
	        .attack_length = e.attack_length,
	        .attack_level = e.attack_level,
	        .fade_length = e.fade_length,
	        .fade_level = e.fade_level,
	};
}

template <typename T>
T get(const json & j, const char * key)
{
	auto it = j.find(key);
	if (it == j.end())
		return T{};
	if (not it->is_number_integer())
		throw std::invalid_argument(std::string("wheel helper: ") + key + " is not an integer");
	auto v = it->get<int64_t>();
	if (v < std::numeric_limits<T>::min() or v > std::numeric_limits<T>::max())
		throw std::out_of_range(std::string("wheel helper: ") + key + " out of range");
	return T(v);
}

ff_envelope envelope_from_json(const json & j)
{
	if (not j.is_object())
		return {};
	return {
	        .attack_length = get<uint16_t>(j, "attack_length"),
	        .attack_level = get<uint16_t>(j, "attack_level"),
	        .fade_length = get<uint16_t>(j, "fade_length"),
	        .fade_level = get<uint16_t>(j, "fade_level"),
	};
}

json member(const json & j, const char * key)
{
	auto it = j.find(key);
	return it == j.end() ? json::object() : *it;
}

// The helper sends the kernel's struct ff_effect as JSON, field names as in linux/input.h
ff_effect ff_effect_from_json(const json & j)
{
	if (not j.is_object())
		throw std::invalid_argument("wheel helper: effect is not an object");
	ff_effect e{};
	e.type = get<uint16_t>(j, "type");
	e.id = get<int16_t>(j, "id");
	e.direction = get<uint16_t>(j, "direction");
	e.trigger.button = get<uint16_t>(j, "trigger_button");
	e.trigger.interval = get<uint16_t>(j, "trigger_interval");
	e.replay.length = get<uint16_t>(j, "replay_length");
	e.replay.delay = get<uint16_t>(j, "replay_delay");
	switch (e.type)
	{
		case FF_CONSTANT: {
			auto c = member(j, "constant");
			e.u.constant.level = get<int16_t>(c, "level");
			e.u.constant.envelope = envelope_from_json(member(c, "envelope"));
			break;
		}
		case FF_RAMP: {
			auto r = member(j, "ramp");
			e.u.ramp.start_level = get<int16_t>(r, "start_level");
			e.u.ramp.end_level = get<int16_t>(r, "end_level");
			e.u.ramp.envelope = envelope_from_json(member(r, "envelope"));
			break;
		}
		case FF_PERIODIC: {
			auto p = member(j, "periodic");
			e.u.periodic.waveform = get<uint16_t>(p, "waveform");
			e.u.periodic.period = get<uint16_t>(p, "period");
			e.u.periodic.magnitude = get<int16_t>(p, "magnitude");
			e.u.periodic.offset = get<int16_t>(p, "offset");
			e.u.periodic.phase = get<uint16_t>(p, "phase");
			e.u.periodic.envelope = envelope_from_json(member(p, "envelope"));
			break;
		}
		case FF_SPRING:
		case FF_FRICTION:
		case FF_DAMPER:
		case FF_INERTIA: {
			auto c = j.find("condition");
			if (c == j.end())
				break;
			if (not c->is_array() or c->size() > 2)
				throw std::invalid_argument("wheel helper: condition is not an array of 2");
			for (size_t i = 0; i < c->size(); ++i)
			{
				const auto & ci = (*c)[i];
				e.u.condition[i].right_saturation = get<uint16_t>(ci, "right_saturation");
				e.u.condition[i].left_saturation = get<uint16_t>(ci, "left_saturation");
				e.u.condition[i].right_coeff = get<int16_t>(ci, "right_coeff");
				e.u.condition[i].left_coeff = get<int16_t>(ci, "left_coeff");
				e.u.condition[i].deadband = get<uint16_t>(ci, "deadband");
				e.u.condition[i].center = get<int16_t>(ci, "center");
			}
			break;
		}
		case FF_RUMBLE: {
			auto r = member(j, "rumble");
			e.u.rumble.strong_magnitude = get<uint16_t>(r, "strong_magnitude");
			e.u.rumble.weak_magnitude = get<uint16_t>(r, "weak_magnitude");
			break;
		}
		default:
			throw std::invalid_argument("wheel helper: unknown effect type " + std::to_string(e.type));
	}
	return e;
}

class helper_backend : public backend
{
	std::string path;
	int fd = -1;
	std::vector<char> buf = std::vector<char>(65536);
	// Wheels created on this connection, and those lost since the last poll
	std::set<uint8_t> live;
	std::vector<lost_wheel> lost;

	void disconnect()
	{
		if (fd >= 0)
			::close(fd);
		fd = -1;
		// The helper destroys a closed connection's wheels
		for (auto id: live)
			lost.push_back({id, false});
		live.clear();
	}

	void connect()
	{
		sockaddr_un addr{.sun_family = AF_UNIX};
		if (path.size() >= sizeof(addr.sun_path))
			throw std::invalid_argument("DIREWOLF_WHEEL_SOCKET path too long");
		std::memcpy(addr.sun_path, path.data(), path.size());

		int s = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
		if (s < 0)
			throw std::system_error(errno, std::generic_category(), "wheel helper socket");
		// A stalled helper must not stall the network thread for long; also bounds connect
		timeval timeout{.tv_sec = 0, .tv_usec = 200'000};
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (::connect(s, (sockaddr *)&addr, sizeof(addr)) < 0)
		{
			int e = errno;
			::close(s);
			throw std::system_error(e, std::generic_category(), "connect to wheel helper " + path);
		}
		fd = s;
	}

	void send_json(const json & j)
	{
		if (fd < 0)
			throw std::runtime_error("not connected to the wheel helper");
		auto s = j.dump();
		if (s.size() > 65536)
			throw std::length_error("wheel helper packet too large");
		if (::send(fd, s.data(), s.size(), MSG_NOSIGNAL) != (ssize_t)s.size())
		{
			int e = errno;
			disconnect();
			throw std::system_error(e, std::generic_category(), "send to wheel helper");
		}
	}

	void parse(const json & j, std::vector<to_headset::wheel_ff> & ff, std::vector<std::string> & errors)
	{
		auto op = j.value("op", "");
		if (op == "created")
			return;
		if (op == "error")
		{
			errors.push_back("wheel helper: " + j.value("msg", std::string("error")) + " (wheel " + std::to_string(j.value("id", -1)) + ")");
			// A refused create, or events for a wheel the helper does not have: the wheel is gone
			if (auto id = j.find("id"); id != j.end() and id->is_number_unsigned() and id->get<uint64_t>() <= 255)
			{
				if (live.erase(id->get<uint8_t>()))
					lost.push_back({id->get<uint8_t>(), true});
			}
			return;
		}
		if (op != "ff")
			throw std::invalid_argument("wheel helper: unknown op " + op);

		to_headset::wheel_ff out{.id = get<uint8_t>(j, "id")};
		auto kind = j.value("kind", "");
		using operation = to_headset::wheel_ff::operation;
		if (kind == "upload")
		{
			auto e = ff_effect_from_json(member(j, "effect"));
			out.op = operation::upload;
			out.effect_id = e.id;
			out.effect = from_kernel(e);
			if (not out.effect)
				return;
		}
		else if (kind == "erase" or kind == "play" or kind == "stop")
		{
			out.op = kind == "erase" ? operation::erase : kind == "play" ? operation::play
			                                                             : operation::stop;
			out.effect_id = get<int16_t>(j, "effect_id");
			out.value = get<int32_t>(j, "value");
			if (out.op == operation::play and out.value == 0)
				out.op = operation::stop;
		}
		else if (kind == "gain" or kind == "autocenter")
		{
			out.op = kind == "gain" ? operation::gain : operation::autocenter;
			out.value = std::clamp<int32_t>(get<int32_t>(j, "value"), 0, 0xffff);
		}
		else
			throw std::invalid_argument("wheel helper: unknown ff kind " + kind);
		ff.push_back(std::move(out));
	}

public:
	explicit helper_backend(std::string path) :
	        path(std::move(path)) {}

	~helper_backend()
	{
		disconnect();
	}

	void create(const from_headset::wheel_added & desc) override
	{
		if (fd < 0)
			connect();

		json abs = json::array();
		for (const auto & a: desc.axes)
			abs.push_back({{"code", a.code}, {"min", a.min}, {"max", a.max}, {"fuzz", a.fuzz}, {"flat", a.flat}});
		json keys = json::array();
		for (auto k: desc.keys)
			if (k)
				keys.push_back(k);
		send_json({
		        {"op", "create"},
		        {"id", desc.id},
		        {"name", desc.name},
		        {"vendor", desc.vendor},
		        {"product", desc.product},
		        {"version", desc.version},
		        {"abs", std::move(abs)},
		        {"keys", std::move(keys)},
		        {"ff", desc.ff},
		        {"ff_effects_max", desc.ff_effects_max},
		});
		live.insert(desc.id);
		std::erase_if(lost, [&](const auto & l) { return l.id == desc.id; });
	}

	void destroy(uint8_t id) override
	{
		live.erase(id);
		std::erase_if(lost, [&](const auto & l) { return l.id == id; });
		if (fd >= 0)
			send_json({{"op", "destroy"}, {"id", id}});
	}

	void send(uint8_t id, std::span<const event> events) override
	{
		json e = json::array();
		for (const auto & ev: events)
			e.push_back({{"type", ev.type}, {"code", ev.code}, {"value", ev.value}});
		send_json({{"op", "events"}, {"id", id}, {"events", std::move(e)}});
	}

	void poll(std::vector<to_headset::wheel_ff> & ff, std::vector<std::string> & errors, std::vector<lost_wheel> & lost_ids) override
	{
		poll_socket(ff, errors);
		lost_ids.insert(lost_ids.end(), lost.begin(), lost.end());
		lost.clear();
	}

	void poll_socket(std::vector<to_headset::wheel_ff> & ff, std::vector<std::string> & errors)
	{
		while (fd >= 0)
		{
			auto n = ::recv(fd, buf.data(), buf.size(), MSG_DONTWAIT | MSG_TRUNC);
			if (n < 0 and (errno == EAGAIN or errno == EWOULDBLOCK or errno == EINTR))
				return;
			if (n <= 0)
			{
				errors.push_back(n == 0 ? "wheel helper closed the connection" : std::string("wheel helper: ") + strerror(errno));
				disconnect();
				return;
			}
			if ((size_t)n > buf.size())
			{
				errors.push_back("wheel helper: packet too large");
				continue;
			}
			auto j = json::parse(buf.begin(), buf.begin() + n, nullptr, false);
			try
			{
				if (not j.is_object())
					throw std::invalid_argument("wheel helper: not a JSON object");
				parse(j, ff, errors);
			}
			catch (const std::exception & e)
			{
				errors.push_back(e.what());
			}
		}
	}
};

} // namespace

std::unique_ptr<backend> make_helper_backend(std::string path)
{
	return std::make_unique<helper_backend>(std::move(path));
}

from_headset::wheel_added sanitize(from_headset::wheel_added desc)
{
	for (auto & c: desc.name)
		if (c < 0x20 or c > 0x7e)
			c = '?';
	if (desc.name.size() > max_name_length)
		desc.name.resize(max_name_length);
	if (desc.name.empty())
		desc.name = "WiVRn wheel";

	std::vector<from_headset::wheel_added::axis> axes;
	for (const auto & a: desc.axes)
	{
		if (a.code > max_abs or a.min >= a.max)
			continue;
		if (std::ranges::any_of(axes, [&](const auto & b) { return b.code == a.code; }))
			continue;
		axes.push_back(a);
	}
	desc.axes = std::move(axes);

	// Indices matter (wheel_state's bitmap): replace, don't remove
	constexpr size_t max_keys = (BTN_GEAR_UP - BTN_MISC + 1) + (BTN_TRIGGER_HAPPY40 - BTN_TRIGGER_HAPPY1 + 1);
	if (desc.keys.size() > max_keys * 2)
		desc.keys.resize(max_keys * 2);
	for (size_t i = 0; i < desc.keys.size(); ++i)
	{
		auto k = desc.keys[i];
		if (not allowed_key(k) or std::find(desc.keys.begin(), desc.keys.begin() + i, k) != desc.keys.begin() + i)
			desc.keys[i] = 0;
	}

	std::vector<uint16_t> ff;
	for (auto f: desc.ff)
		if (allowed_ff(f) and std::ranges::find(ff, f) == ff.end())
			ff.push_back(f);
	if (std::ranges::none_of(ff, is_effect_type))
		ff.clear();
	desc.ff = std::move(ff);
	desc.ff_effects_max = desc.ff.empty() ? 0 : std::clamp<uint8_t>(desc.ff_effects_max, 1, max_ff_effects);

	return desc;
}

std::optional<wheel_ff_effect> from_kernel(const ff_effect & e)
{
	wheel_ff_effect out{
	        .type = e.type,
	        .direction = e.direction,
	        .trigger_button = e.trigger.button,
	        .trigger_interval = e.trigger.interval,
	        .replay_length = e.replay.length,
	        .replay_delay = e.replay.delay,
	};
	switch (e.type)
	{
		case FF_CONSTANT:
			out.u = wheel_ff_effect::constant{
			        .level = e.u.constant.level,
			        .envelope = envelope(e.u.constant.envelope),
			};
			break;
		case FF_RAMP:
			out.u = wheel_ff_effect::ramp{
			        .start_level = e.u.ramp.start_level,
			        .end_level = e.u.ramp.end_level,
			        .envelope = envelope(e.u.ramp.envelope),
			};
			break;
		case FF_PERIODIC:
			if (e.u.periodic.waveform == FF_CUSTOM)
				return std::nullopt;
			out.u = wheel_ff_effect::periodic{
			        .waveform = e.u.periodic.waveform,
			        .period = e.u.periodic.period,
			        .magnitude = e.u.periodic.magnitude,
			        .offset = e.u.periodic.offset,
			        .phase = e.u.periodic.phase,
			        .envelope = envelope(e.u.periodic.envelope),
			};
			break;
		case FF_SPRING:
		case FF_FRICTION:
		case FF_DAMPER:
		case FF_INERTIA: {
			std::array<wheel_ff_effect::condition, 2> c;
			for (size_t i = 0; i < 2; ++i)
				c[i] = {
				        .right_saturation = e.u.condition[i].right_saturation,
				        .left_saturation = e.u.condition[i].left_saturation,
				        .right_coeff = e.u.condition[i].right_coeff,
				        .left_coeff = e.u.condition[i].left_coeff,
				        .deadband = e.u.condition[i].deadband,
				        .center = e.u.condition[i].center,
				};
			out.u = c;
			break;
		}
		case FF_RUMBLE:
			out.u = wheel_ff_effect::rumble{
			        .strong_magnitude = e.u.rumble.strong_magnitude,
			        .weak_magnitude = e.u.rumble.weak_magnitude,
			};
			break;
		default:
			return std::nullopt;
	}
	return out;
}

manager::manager(std::unique_ptr<backend> sink) :
        sink(std::move(sink)) {}

manager::~manager()
{
	clear();
}

void manager::fail(device & d, const std::exception & e)
{
	errors.push_back("wheel " + std::to_string(d.desc.id) + ": " + e.what());
	if (d.created)
	{
		try
		{
			sink->destroy(d.desc.id);
		}
		catch (...)
		{}
	}
	// Connect and send errors: the helper is down or restarting, retry soon
	back_off(d, false);
}

void manager::back_off(device & d, bool escalate)
{
	// A wheel the helper refuses for its content is refused every time: don't retry it every
	// second forever. A wheel that worked for a while starts again at 1 s.
	auto now = std::chrono::steady_clock::now();
	if (d.created and now - d.created_at > healthy_after)
		d.failures = 0;
	d.created = false;
	if (escalate)
	{
		d.retry_at = now + std::chrono::seconds(1 << d.failures); // 1 s .. 64 s
		d.failures = std::min(d.failures + 1, 6);
	}
	else
		d.retry_at = now + std::chrono::seconds(1);
}

void manager::try_create(device & d)
{
	if (std::chrono::steady_clock::now() < d.retry_at)
		return;
	try
	{
		sink->create(d.desc);
		d.created = true;
		d.created_at = std::chrono::steady_clock::now();
		// Every value is sent again on the next state
		std::ranges::fill(d.abs, std::numeric_limits<int32_t>::min());
		d.keys.assign(d.desc.keys.size(), false);
	}
	catch (const std::exception & e)
	{
		fail(d, e);
	}
}

void manager::add(from_headset::wheel_added desc)
{
	remove(desc.id);
	if (devices.size() >= max_wheels)
	{
		errors.push_back("wheel " + std::to_string(desc.id) + ": too many wheels");
		return;
	}
	desc = sanitize(std::move(desc));
	if (desc.axes.empty() and std::ranges::all_of(desc.keys, [](uint16_t k) { return k == 0; }))
	{
		errors.push_back("wheel " + std::to_string(desc.id) + ": no usable axis or button");
		return;
	}
	device d{
	        .desc = std::move(desc),
	        .abs = std::vector<int32_t>(max_abs + 1, std::numeric_limits<int32_t>::min()),
	};
	d.keys.assign(d.desc.keys.size(), false);
	auto & dev = devices.emplace(d.desc.id, std::move(d)).first->second;
	try_create(dev);
}

void manager::remove(uint8_t id)
{
	auto it = devices.find(id);
	if (it == devices.end())
		return;
	if (it->second.created)
	{
		try
		{
			sink->destroy(id);
		}
		catch (const std::exception & e)
		{
			errors.push_back("wheel " + std::to_string(id) + ": " + e.what());
		}
	}
	devices.erase(it);
}

void manager::clear()
{
	while (not devices.empty())
		remove(devices.begin()->first);
}

void manager::state(const from_headset::wheel_state & state)
{
	auto it = devices.find(state.id);
	if (it == devices.end())
		return;
	auto & d = it->second;
	if (not d.created)
	{
		try_create(d);
		if (not d.created)
			return;
	}

	// At most one event per axis and key, so a packet stays under the helper's 256 events
	// (≤ 41 axes + ≤ 122 distinct keys + SYN)
	std::vector<event> events;
	std::bitset<max_abs + 1> seen;
	for (const auto & v: state.axes)
	{
		auto a = std::ranges::find_if(d.desc.axes, [&](const auto & a) { return a.code == v.code; });
		if (a == d.desc.axes.end() or seen[v.code])
			continue;
		seen[v.code] = true;
		auto value = std::clamp(v.value, a->min, a->max);
		if (d.abs[v.code] == value)
			continue;
		d.abs[v.code] = value;
		events.push_back({EV_ABS, v.code, value});
	}
	for (size_t i = 0; i < d.desc.keys.size() and i / 8 < state.keys.size(); ++i)
	{
		if (d.desc.keys[i] == 0)
			continue;
		bool down = (state.keys[i / 8] >> (i % 8)) & 1;
		if (d.keys[i] == down)
			continue;
		d.keys[i] = down;
		events.push_back({EV_KEY, d.desc.keys[i], down});
	}
	if (events.empty())
		return;
	events.push_back({EV_SYN, SYN_REPORT, 0});

	try
	{
		sink->send(d.desc.id, events);
	}
	catch (const std::exception & e)
	{
		fail(d, e);
	}
}

std::vector<to_headset::wheel_ff> manager::poll_ff()
{
	std::vector<to_headset::wheel_ff> ff;
	std::vector<lost_wheel> lost;
	try
	{
		sink->poll(ff, errors, lost);
	}
	catch (const std::exception & e)
	{
		errors.push_back(e.what());
	}
	// Recreated on their next state, after the usual backoff
	for (auto [id, refused]: lost)
	{
		if (auto it = devices.find(id); it != devices.end() and it->second.created)
			back_off(it->second, refused);
	}
	std::erase_if(ff, [&](const auto & f) {
		auto it = devices.find(f.id);
		return it == devices.end() or not it->second.created;
	});
	return ff;
}

std::vector<std::string> manager::take_errors()
{
	return std::exchange(errors, {});
}

} // namespace wivrn::wheel
