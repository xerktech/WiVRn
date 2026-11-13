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

// Tests for the wheel packets and the server's virtual wheels (XERK-2850): serialization,
// sanitizing, the fenrir helper socket against a fake helper, and a real uinput device with a
// force-feedback upload round trip (needs /dev/uinput; WIVRN_REQUIRE_UINPUT=1 makes its absence
// a failure). Built standalone in CI (.github/workflows/Sockets-UT.yml).
#include "wivrn_packets.h"
#include "wivrn_serialization.h"
#include "wivrn_uinput.h"
#include "wivrn_wheel.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <future>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

using namespace wivrn;
using namespace std::chrono_literals;
using json = nlohmann::json;

static int failures = 0;
#define CHECK(c)                                                            \
	do                                                                  \
	{                                                                   \
		if (!(c))                                                   \
		{                                                           \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
			++failures;                                         \
		}                                                           \
		else                                                        \
			printf("ok   %s\n", #c);                            \
	} while (0)

template <typename T>
static T round_trip(const T & in)
{
	serialization_packet p;
	p.serialize(in);
	std::vector<uint8_t> bytes;
	for (auto span: (std::vector<std::span<uint8_t>> &)p)
		bytes.insert(bytes.end(), span.begin(), span.end());
	std::shared_ptr<uint8_t[]> mem(new uint8_t[bytes.size()]);
	std::memcpy(mem.get(), bytes.data(), bytes.size());
	deserialization_packet d(mem, {mem.get(), bytes.size()});
	auto out = d.deserialize<T>();
	CHECK(d.empty());
	return out;
}

static from_headset::wheel_added g920(uint8_t id = 1)
{
	return {
	        .id = id,
	        .vendor = 0x046d,
	        .product = 0xc262,
	        .version = 0x0111,
	        .name = "Logitech G920 Driving Force Racing Wheel",
	        .axes = {
	                {ABS_X, 0, 65535, 0, 0},
	                {ABS_Y, 0, 255, 0, 0},
	                {ABS_Z, 0, 255, 0, 0},
	                {ABS_RZ, 0, 255, 0, 0},
	                {ABS_HAT0X, -1, 1, 0, 0},
	                {ABS_HAT0Y, -1, 1, 0, 0},
	        },
	        .keys = {BTN_TRIGGER, BTN_THUMB, BTN_THUMB2, BTN_TOP, BTN_TOP2, BTN_PINKIE, BTN_BASE, BTN_BASE2, BTN_BASE3, BTN_BASE4, BTN_BASE5},
	        .ff = {FF_CONSTANT, FF_SPRING, FF_DAMPER, FF_PERIODIC, FF_SINE, FF_GAIN, FF_AUTOCENTER},
	        .ff_effects_max = 16,
	};
}

static void test_serialization()
{
	{
		auto in = g920();
		from_headset::packets p = in;
		auto out = std::get<from_headset::wheel_added>(round_trip(p));
		CHECK(out.id == 1 and out.vendor == 0x046d and out.product == 0xc262 and out.version == 0x0111);
		CHECK(out.name == in.name);
		CHECK(out.axes.size() == 6 and out.axes[0].code == ABS_X and out.axes[0].max == 65535 and out.axes[4].min == -1);
		CHECK(out.keys == in.keys);
		CHECK(out.ff == in.ff);
		CHECK(out.ff_effects_max == 16);
	}
	{
		from_headset::packets p = from_headset::wheel_state{
		        .id = 3,
		        .axes = {{ABS_X, 40000}, {ABS_HAT0X, -1}},
		        .keys = {0x05, 0x04},
		};
		auto out = std::get<from_headset::wheel_state>(round_trip(p));
		CHECK(out.id == 3 and out.axes.size() == 2 and out.axes[0].value == 40000 and out.axes[1].value == -1);
		CHECK((out.keys == std::vector<uint8_t>{0x05, 0x04}));
	}
	{
		from_headset::packets p = from_headset::wheel_removed{.id = 7};
		CHECK(std::get<from_headset::wheel_removed>(round_trip(p)).id == 7);
	}
	{
		using op = to_headset::wheel_ff::operation;
		to_headset::packets p = to_headset::wheel_ff{
		        .id = 2,
		        .op = op::upload,
		        .effect_id = 5,
		        .effect = wheel_ff_effect{
		                .type = FF_SPRING,
		                .direction = 0x4000,
		                .replay_length = 1000,
		                .u = std::array<wheel_ff_effect::condition, 2>{{{0x7fff, 0x7ffe, -1000, 2000, 10, -300}, {}}},
		        },
		};
		auto out = std::get<to_headset::wheel_ff>(round_trip(p));
		CHECK(out.id == 2 and out.op == op::upload and out.effect_id == 5);
		CHECK(out.effect and out.effect->type == FF_SPRING and out.effect->direction == 0x4000 and out.effect->replay_length == 1000);
		auto & c = std::get<std::array<wheel_ff_effect::condition, 2>>(out.effect->u);
		CHECK(c[0].right_saturation == 0x7fff and c[0].left_coeff == 2000 and c[0].right_coeff == -1000 and c[0].center == -300);

		p = to_headset::wheel_ff{.id = 2, .op = op::gain, .value = 0xc000};
		out = std::get<to_headset::wheel_ff>(round_trip(p));
		CHECK(out.op == op::gain and out.value == 0xc000 and not out.effect);
	}
}

static void test_sanitize()
{
	auto d = g920();
	d.name = std::string(200, 'x') + "\n";
	d.name[3] = '\x01';
	d.axes.push_back({ABS_X, 0, 10, 0, 0});      // duplicate
	d.axes.push_back({ABS_MT_SLOT, 0, 9, 0, 0}); // not a wheel axis
	d.axes.push_back({ABS_RX, 5, 1, 0, 0});      // min > max
	d.keys.push_back(KEY_A);                     // keyboard key
	d.keys.push_back(BTN_TRIGGER);               // duplicate
	d.keys.push_back(BTN_TRIGGER_HAPPY3);
	d.ff.push_back(FF_CUSTOM);
	d.ff.push_back(0x7f);
	d.ff_effects_max = 200;

	auto s = wheel::sanitize(d);
	CHECK(s.name.size() == wheel::max_name_length and s.name[3] == '?');
	CHECK(s.axes.size() == 6);
	CHECK(s.keys.size() == d.keys.size());
	CHECK(s.keys[11] == 0 and s.keys[12] == 0 and s.keys[13] == BTN_TRIGGER_HAPPY3);
	CHECK(s.ff.size() == 7);
	CHECK(s.ff_effects_max == wheel::max_ff_effects);

	d = g920();
	d.ff = {FF_GAIN}; // no effect type: no force feedback at all
	d.ff_effects_max = 16;
	s = wheel::sanitize(d);
	CHECK(s.ff.empty() and s.ff_effects_max == 0);

	d.ff = {FF_CONSTANT};
	d.ff_effects_max = 0;
	d.name = "";
	s = wheel::sanitize(d);
	CHECK(s.ff_effects_max == 1 and not s.name.empty());
}

struct fake_backend : wheel::backend
{
	std::vector<std::string> log;
	std::vector<std::vector<wheel::event>> sent;
	std::vector<to_headset::wheel_ff> pending;
	int fail_create = 0;
	int fail_send = 0;

	void create(const from_headset::wheel_added & d) override
	{
		if (fail_create and fail_create--)
			throw std::runtime_error("create failed");
		log.push_back("create " + std::to_string(d.id));
	}
	void destroy(uint8_t id) override
	{
		log.push_back("destroy " + std::to_string(id));
	}
	void send(uint8_t, std::span<const wheel::event> e) override
	{
		if (fail_send and fail_send--)
			throw std::runtime_error("send failed");
		sent.emplace_back(e.begin(), e.end());
	}
	void poll(std::vector<to_headset::wheel_ff> & ff, std::vector<std::string> &) override
	{
		ff.insert(ff.end(), pending.begin(), pending.end());
		pending.clear();
	}
};

static void test_manager()
{
	auto owned = std::make_unique<fake_backend>();
	auto & b = *owned;
	wheel::manager m(std::move(owned));

	m.add(g920(1));
	CHECK((b.log == std::vector<std::string>{"create 1"}));

	// First state sends every listed value; out-of-range values are clamped
	m.state({.id = 1, .axes = {{ABS_X, 70000}, {ABS_Y, 3}}, .keys = {0b101}});
	CHECK(b.sent.size() == 1);
	CHECK((b.sent.back() == std::vector<wheel::event>{
	                                {EV_ABS, ABS_X, 65535},
	                                {EV_ABS, ABS_Y, 3},
	                                {EV_KEY, BTN_TRIGGER, 1},
	                                {EV_KEY, BTN_THUMB2, 1},
	                                {EV_SYN, SYN_REPORT, 0},
	                        }));

	// Only changes are sent; an unchanged state sends nothing
	m.state({.id = 1, .axes = {{ABS_X, 65535}, {ABS_Y, 4}}, .keys = {0b001}});
	CHECK((b.sent.back() == std::vector<wheel::event>{{EV_ABS, ABS_Y, 4}, {EV_KEY, BTN_THUMB2, 0}, {EV_SYN, SYN_REPORT, 0}}));
	m.state({.id = 1, .axes = {{ABS_Y, 4}}, .keys = {0b001}});
	CHECK(b.sent.size() == 2);

	// Undeclared axes and unknown wheels are ignored
	m.state({.id = 1, .axes = {{ABS_RX, 4}}});
	m.state({.id = 9, .axes = {{ABS_X, 4}}});
	CHECK(b.sent.size() == 2);

	// FF for unknown wheels is dropped
	b.pending = {{.id = 1, .op = to_headset::wheel_ff::operation::gain, .value = 1}, {.id = 9}};
	auto ff = m.poll_ff();
	CHECK(ff.size() == 1 and ff[0].id == 1);

	// A send failure destroys the device; it is created again after a second
	b.fail_send = 1;
	m.state({.id = 1, .axes = {{ABS_Y, 5}}});
	CHECK(b.log.back() == "destroy 1");
	CHECK(m.take_errors().size() == 1);
	m.state({.id = 1, .axes = {{ABS_Y, 6}}});
	CHECK(b.log.back() == "destroy 1"); // still waiting
	std::this_thread::sleep_for(1100ms);
	m.state({.id = 1, .axes = {{ABS_Y, 6}}, .keys = {0}});
	CHECK(b.log.back() == "create 1");
	// The new device gets every value again
	CHECK((b.sent.back() == std::vector<wheel::event>{{EV_ABS, ABS_Y, 6}, {EV_SYN, SYN_REPORT, 0}}));

	// Re-adding an id replaces it; at most max_wheels
	m.add(g920(1));
	CHECK(b.log[b.log.size() - 2] == "destroy 1" and b.log.back() == "create 1");
	for (uint8_t i = 2; i <= wheel::max_wheels + 1; ++i)
		m.add(g920(i));
	CHECK(m.size() == wheel::max_wheels);
	CHECK(m.take_errors().size() == 1);

	m.clear();
	CHECK(m.size() == 0);
	CHECK(std::ranges::count(b.log, std::string("destroy 2")) == 1);
}

// A fake fenrir helper on a SOCK_SEQPACKET socket
struct fake_helper
{
	std::string path;
	int listener = -1;
	int conn = -1;

	fake_helper()
	{
		path = (std::filesystem::temp_directory_path() / ("wivrn_wheel_ut." + std::to_string(getpid()))).string();
		::unlink(path.c_str());
		listener = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
		sockaddr_un addr{.sun_family = AF_UNIX};
		std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
		if (::bind(listener, (sockaddr *)&addr, sizeof(addr)) or ::listen(listener, 4))
			perror("fake helper");
	}
	~fake_helper()
	{
		if (conn >= 0)
			::close(conn);
		::close(listener);
		::unlink(path.c_str());
	}
	bool accept()
	{
		pollfd p{.fd = listener, .events = POLLIN};
		if (::poll(&p, 1, 2000) != 1)
			return false;
		if (conn >= 0)
			::close(conn);
		conn = ::accept(listener, nullptr, nullptr);
		return conn >= 0;
	}
	json recv()
	{
		pollfd p{.fd = conn, .events = POLLIN};
		if (::poll(&p, 1, 2000) != 1)
			return nullptr;
		char buf[65536];
		auto n = ::recv(conn, buf, sizeof(buf), 0);
		if (n <= 0)
			return nullptr;
		return json::parse(buf, buf + n, nullptr, false);
	}
	void send(const std::string & s)
	{
		::send(conn, s.data(), s.size(), MSG_NOSIGNAL);
	}
};

static std::vector<to_headset::wheel_ff> poll_until(wheel::manager & m, size_t n)
{
	std::vector<to_headset::wheel_ff> all;
	for (int i = 0; i < 200 and all.size() < n; ++i)
	{
		auto ff = m.poll_ff();
		all.insert(all.end(), ff.begin(), ff.end());
		if (all.size() < n)
			std::this_thread::sleep_for(10ms);
	}
	return all;
}

static void test_helper_socket()
{
	using op = to_headset::wheel_ff::operation;
	fake_helper h;
	wheel::manager m(wheel::make_helper_backend(h.path));

	// The helper's absence is an error, retried later, not a crash
	{
		wheel::manager none(wheel::make_helper_backend(h.path + ".missing"));
		none.add(g920(1));
		CHECK(none.take_errors().size() == 1);
	}

	auto d = g920(1);
	d.keys.push_back(KEY_A);
	m.add(d);
	CHECK(h.accept());
	auto create = h.recv();
	CHECK(create["op"] == "create" and create["id"] == 1 and create["vendor"] == 0x046d and create["product"] == 0xc262);
	CHECK(create["name"] == d.name);
	CHECK(create["abs"].size() == 6 and create["abs"][0]["code"] == ABS_X and create["abs"][0]["max"] == 65535);
	CHECK(create["keys"].size() == 11); // KEY_A dropped
	CHECK(create["ff"].size() == 7 and create["ff_effects_max"] == 16);

	m.state({.id = 1, .axes = {{ABS_X, 1234}}, .keys = {0b10}});
	auto ev = h.recv();
	CHECK(ev["op"] == "events" and ev["id"] == 1 and ev["events"].size() == 3);
	CHECK(ev["events"][0] == json({{"type", EV_ABS}, {"code", ABS_X}, {"value", 1234}}));
	CHECK(ev["events"][1] == json({{"type", EV_KEY}, {"code", BTN_THUMB}, {"value", 1}}));

	h.send(R"({"op":"created","id":1})");
	h.send(R"({"op":"ff","id":1,"kind":"upload","effect":{"type":82,"id":3,"direction":16384,"replay_length":500,"constant":{"level":-12000,"envelope":{"attack_length":10,"attack_level":20,"fade_length":30,"fade_level":40}}}})");
	h.send(R"({"op":"ff","id":1,"kind":"play","effect_id":3,"value":2})");
	h.send(R"({"op":"ff","id":1,"kind":"play","effect_id":3,"value":0})");
	h.send(R"({"op":"ff","id":1,"kind":"stop","effect_id":3})");
	h.send(R"({"op":"ff","id":1,"kind":"erase","effect_id":3})");
	h.send(R"({"op":"ff","id":1,"kind":"gain","value":70000})");
	h.send(R"({"op":"ff","id":1,"kind":"autocenter","value":0})");
	h.send(R"({"op":"ff","id":9,"kind":"gain","value":1})");                         // unknown wheel
	h.send(R"({"op":"ff","id":1,"kind":"upload","effect":{"type":82,"id":70000}})"); // bad id
	h.send(R"(not json)");
	h.send(R"({"op":"error","id":1,"msg":"nope"})");
	h.send(R"({"op":"ff","id":1,"kind":"upload","effect":{"type":96}})"); // FF_GAIN is no effect

	auto ff = poll_until(m, 7);
	CHECK(ff.size() == 7);
	if (ff.size() == 7)
	{
		CHECK(ff[0].op == op::upload and ff[0].effect_id == 3 and ff[0].effect);
		if (ff[0].effect)
		{
			CHECK(ff[0].effect->type == FF_CONSTANT and ff[0].effect->direction == 16384 and ff[0].effect->replay_length == 500);
			auto & c = std::get<wheel_ff_effect::constant>(ff[0].effect->u);
			CHECK(c.level == -12000 and c.envelope.attack_length == 10 and c.envelope.fade_level == 40);
		}
		CHECK(ff[1].op == op::play and ff[1].effect_id == 3 and ff[1].value == 2);
		CHECK(ff[2].op == op::stop and ff[3].op == op::stop);
		CHECK(ff[4].op == op::erase and ff[4].effect_id == 3);
		CHECK(ff[5].op == op::gain and ff[5].value == 0xffff);
		CHECK(ff[6].op == op::autocenter and ff[6].value == 0);
	}
	CHECK(m.take_errors().size() == 4);

	m.remove(1);
	auto destroy = h.recv();
	CHECK(destroy == json({{"op", "destroy"}, {"id", 1}}));

	// The helper restarts: the wheel is created again on a new connection
	m.add(g920(2));
	CHECK(h.recv()["op"] == "create");
	::close(h.conn);
	h.conn = -1;
	m.poll_ff();
	CHECK(not m.take_errors().empty());
	m.state({.id = 2, .axes = {{ABS_X, 1}}});
	std::this_thread::sleep_for(1100ms);
	m.state({.id = 2, .axes = {{ABS_X, 2}}});
	CHECK(h.accept());
	auto again = h.recv();
	CHECK(again["op"] == "create" and again["id"] == 2);
	auto ev2 = h.recv();
	CHECK(ev2["op"] == "events" and ev2["events"][0]["value"] == 2);
}

static std::string event_node(const std::string & sysname)
{
	for (int i = 0; i < 200; ++i)
	{
		std::error_code ec;
		for (auto & e: std::filesystem::directory_iterator("/sys/devices/virtual/input/" + sysname, ec))
		{
			auto name = e.path().filename().string();
			if (name.starts_with("event") and std::filesystem::exists("/dev/input/" + name))
				return "/dev/input/" + name;
		}
		std::this_thread::sleep_for(10ms);
	}
	return {};
}

static void test_uinput()
{
	using op = to_headset::wheel_ff::operation;
	if (access("/dev/uinput", R_OK | W_OK) != 0)
	{
		bool required = std::getenv("WIVRN_REQUIRE_UINPUT");
		printf("%s uinput test: /dev/uinput not accessible\n", required ? "FAIL" : "SKIP");
		failures += required;
		return;
	}

	auto owned = std::make_unique<wivrn_uinput_wheels>();
	auto & u = *owned;
	wheel::manager m(std::move(owned));
	m.add(g920(1));
	CHECK(m.take_errors().empty());
	auto node = event_node(u.sysname(1));
	CHECK(not node.empty());
	int fd = ::open(node.c_str(), O_RDWR);
	CHECK(fd >= 0);
	if (fd < 0)
		return;

	char name[256]{};
	ioctl(fd, EVIOCGNAME(sizeof(name)), name);
	CHECK(std::string(name) == g920().name);
	input_id id{};
	ioctl(fd, EVIOCGID, &id);
	CHECK(id.vendor == 0x046d and id.product == 0xc262 and id.bustype == BUS_USB);
	int n_effects = 0;
	ioctl(fd, EVIOCGEFFECTS, &n_effects);
	CHECK(n_effects == 16);
	uint8_t ffbits[(FF_CNT + 7) / 8]{};
	ioctl(fd, EVIOCGBIT(EV_FF, sizeof(ffbits)), ffbits);
	auto has_ff = [&](int code) { return (ffbits[code / 8] >> (code % 8)) & 1; };
	CHECK(has_ff(FF_CONSTANT) and has_ff(FF_SPRING) and has_ff(FF_GAIN) and has_ff(FF_AUTOCENTER) and not has_ff(FF_RUMBLE));
	input_absinfo abs{};
	ioctl(fd, EVIOCGABS(ABS_X), &abs);
	CHECK(abs.minimum == 0 and abs.maximum == 65535);

	// State reaches the device
	m.state({.id = 1, .axes = {{ABS_X, 30000}}, .keys = {0b1}});
	input_event ev[8];
	pollfd p{.fd = fd, .events = POLLIN};
	CHECK(::poll(&p, 1, 1000) == 1);
	auto got = ::read(fd, ev, sizeof(ev)) / (ssize_t)sizeof(input_event);
	CHECK(got >= 3);
	if (got >= 3)
	{
		CHECK(ev[0].type == EV_ABS and ev[0].code == ABS_X and ev[0].value == 30000);
		CHECK(ev[1].type == EV_KEY and ev[1].code == BTN_TRIGGER and ev[1].value == 1);
		CHECK(ev[2].type == EV_SYN);
	}

	// FF upload: the game's ioctl blocks until the server answers it
	ff_effect effect{
	        .type = FF_CONSTANT,
	        .id = -1,
	        .direction = 0xc000,
	        .replay = {.length = 2000, .delay = 0},
	        .u = {.constant = {.level = 0x2000, .envelope = {.attack_length = 100, .attack_level = 0x1000}}},
	};
	auto upload = std::async(std::launch::async, [&] { return ioctl(fd, EVIOCSFF, &effect); });
	auto ff = poll_until(m, 1);
	CHECK(upload.wait_for(2s) == std::future_status::ready and upload.get() == 0);
	CHECK(ff.size() == 1);
	if (ff.size() == 1)
	{
		CHECK(ff[0].id == 1 and ff[0].op == op::upload and ff[0].effect_id == effect.id and ff[0].effect);
		if (ff[0].effect)
		{
			CHECK(ff[0].effect->type == FF_CONSTANT and ff[0].effect->direction == 0xc000 and ff[0].effect->replay_length == 2000);
			auto & c = std::get<wheel_ff_effect::constant>(ff[0].effect->u);
			CHECK(c.level == 0x2000 and c.envelope.attack_length == 100 and c.envelope.attack_level == 0x1000);
		}
	}

	// Play, stop, gain, autocenter written by the game
	auto write_ff = [&](uint16_t code, int32_t value) {
		input_event e{.type = EV_FF, .code = code, .value = value};
		return ::write(fd, &e, sizeof(e)) == sizeof(e);
	};
	CHECK(write_ff(effect.id, 1));
	CHECK(write_ff(effect.id, 0));
	CHECK(write_ff(FF_GAIN, 0x8000));
	CHECK(write_ff(FF_AUTOCENTER, 0x4000));
	ff = poll_until(m, 4);
	CHECK(ff.size() == 4);
	if (ff.size() == 4)
	{
		CHECK(ff[0].op == op::play and ff[0].effect_id == effect.id and ff[0].value == 1);
		CHECK(ff[1].op == op::stop and ff[1].effect_id == effect.id);
		CHECK(ff[2].op == op::gain and ff[2].value == 0x8000);
		CHECK(ff[3].op == op::autocenter and ff[3].value == 0x4000);
	}

	// Erase blocks like upload
	auto erase = std::async(std::launch::async, [&] { return ioctl(fd, EVIOCRMFF, effect.id); });
	ff = poll_until(m, 1);
	CHECK(erase.wait_for(2s) == std::future_status::ready and erase.get() == 0);
	CHECK(ff.size() == 1 and ff[0].op == op::erase and ff[0].effect_id == effect.id);

	// Removing the wheel destroys the device
	m.remove(1);
	char buf[sizeof(input_event)];
	CHECK(::poll(&p, 1, 1000) == 1 and ::read(fd, buf, sizeof(buf)) < 0 and errno == ENODEV);
	::close(fd);
}

int main()
{
	test_serialization();
	test_sanitize();
	test_manager();
	test_helper_socket();
	test_uinput();
	if (failures)
		printf("%d failure(s)\n", failures);
	else
		printf("all passed\n");
	return failures ? 1 : 0;
}
