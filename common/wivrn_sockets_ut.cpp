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

// Loopback tests for the authenticated (AES-GCM) TCP and UDP records: round trips,
// and that tampered, replayed, reordered or wrongly keyed records are rejected.
#include "wivrn_sockets.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace wivrn;
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

static std::array<uint8_t, 16> key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static std::array<uint8_t, 16> iv_ab{0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static std::array<uint8_t, 16> iv_ba{0xb0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static std::pair<int, int> tcp_pair()
{
	int l = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a{};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(l, (sockaddr *)&a, sizeof(a));
	socklen_t len = sizeof(a);
	getsockname(l, (sockaddr *)&a, &len);
	listen(l, 1);
	int c = socket(AF_INET, SOCK_STREAM, 0);
	connect(c, (sockaddr *)&a, sizeof(a));
	int s = accept(l, nullptr, nullptr);
	close(l);
	return {c, s};
}

static serialization_packet make(std::vector<uint8_t> & bytes)
{
	// Copy: the sockets encrypt the packet's spans in place
	serialization_packet p;
	p.write(bytes.data(), bytes.size());
	return p;
}

static std::vector<uint8_t> payload(size_t n, uint8_t seed)
{
	std::vector<uint8_t> v(n);
	for (size_t i = 0; i < n; ++i)
		v[i] = uint8_t(seed + i * 7);
	return v;
}

static std::vector<uint8_t> bytes_of(deserialization_packet p)
{
	auto s = p.read_span(p.wire_size());
	return {s.begin(), s.end()};
}

template <typename S>
static deserialization_packet recv_one(S & s)
{
	for (int i = 0; i < 1000; ++i)
	{
		auto p = s.receive_pending();
		if (not p.empty())
			return p;
		pollfd pfd{.fd = (int)s, .events = POLLIN};
		if (poll(&pfd, 1, 200) <= 0)
			return {};
		p = s.receive_raw();
		if (not p.empty())
			return p;
	}
	return {};
}

static std::vector<uint8_t> drain(int fd)
{
	std::vector<uint8_t> out;
	pollfd pfd{.fd = fd, .events = POLLIN};
	while (poll(&pfd, 1, 100) > 0)
	{
		uint8_t buf[65536];
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n <= 0)
			break;
		out.insert(out.end(), buf, buf + n);
	}
	return out;
}

// A (encrypted) -> raw wire -> optional tamper -> B (encrypted)
struct tcp_mitm
{
	TCP a, b;
	int a_raw, b_raw;
	tcp_mitm()
	{
		auto [x, y] = tcp_pair();
		auto [z, w] = tcp_pair();
		a = TCP(x);
		a_raw = y;
		b_raw = z;
		b = TCP(w);
		a.set_aes_key_and_ivs(key, iv_ba, iv_ab);
		b.set_aes_key_and_ivs(key, iv_ab, iv_ba);
	}
};

static void test_tcp()
{
	{
		auto [x, y] = tcp_pair();
		TCP a(x), b(y);
		a.set_aes_key_and_ivs(key, iv_ba, iv_ab);
		b.set_aes_key_and_ivs(key, iv_ab, iv_ba);

		auto p1 = payload(10, 1), p2 = payload(200000, 2), p3 = payload(1, 3), p4 = payload(5000, 4);
		auto big = payload(3 * 1024 * 1024, 9);
		a.send_raw(make(p1));
		std::vector<serialization_packet> many;
		many.push_back(make(p2));
		many.push_back(make(p3));
		many.push_back(make(p4));
		a.send_many_raw(many);
		CHECK(bytes_of(recv_one(b)) == payload(10, 1));
		CHECK(bytes_of(recv_one(b)) == payload(200000, 2));
		CHECK(bytes_of(recv_one(b)) == payload(1, 3));
		CHECK(bytes_of(recv_one(b)) == payload(5000, 4));
		// Other direction, and a record larger than the socket buffers
		std::thread t([&] { b.send_raw(make(big)); });
		CHECK(bytes_of(recv_one(a)) == payload(3 * 1024 * 1024, 9));
		t.join();
	}

	// A lowered payload limit rejects a larger record from its length prefix, before buffering it;
	// restoring the limit accepts it again
	{
		auto [x, y] = tcp_pair();
		TCP a(x), b(y);
		b.set_max_payload(64 * 1024);
		auto p5 = payload(64 * 1024, 5), p6 = payload(64 * 1024 + 1, 6);
		a.send_raw(make(p5));
		CHECK(bytes_of(recv_one(b)) == payload(64 * 1024, 5));
		a.send_raw(make(p6));
		bool threw = false;
		try
		{
			recv_one(b);
		}
		catch (std::runtime_error & e)
		{
			threw = std::string(e.what()).starts_with("Invalid packet: size");
		}
		CHECK(threw);
	}
	{
		auto [x, y] = tcp_pair();
		TCP a(x), b(y);
		b.set_max_payload(64 * 1024);
		b.set_max_payload(TCP::default_max_payload);
		auto p7 = payload(1024 * 1024, 7);
		std::thread t([&] { a.send_raw(make(p7)); });
		CHECK(bytes_of(recv_one(b)) == payload(1024 * 1024, 7));
		t.join();
	}

	auto forward_and_receive = [](tcp_mitm & m, auto && tamper) -> std::string {
		auto wire = drain(m.a_raw);
		tamper(wire);
		send(m.b_raw, wire.data(), wire.size(), 0);
		try
		{
			std::string out;
			for (int i = 0; i < 2; ++i)
			{
				auto p = recv_one(m.b);
				if (p.empty())
					break;
				auto v = bytes_of(p);
				out += std::string(v.begin(), v.end()) + "|";
			}
			return out;
		}
		catch (std::exception & e)
		{
			return std::string("THROW:") + e.what();
		}
	};

	{
		tcp_mitm m;
		std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
		m.a.send_raw(make(msg));
		auto r = forward_and_receive(m, [](auto &) {});
		CHECK(r == "hello|");
		// Wire carries ciphertext, not the plaintext
		m.a.send_raw(make(msg));
		auto wire = drain(m.a_raw);
		CHECK(wire.size() == 4 + 5 + 16);
		CHECK(memcmp(wire.data() + 4, "hello", 5) != 0);
	}
	{
		tcp_mitm m;
		std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
		m.a.send_raw(make(msg));
		// Flip one payload bit (the CTR attack): must be rejected
		auto r = forward_and_receive(m, [](auto & w) { w[4] ^= 0x01; });
		CHECK(r.starts_with("THROW:"));
	}
	{
		tcp_mitm m;
		std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
		m.a.send_raw(make(msg));
		// Flip a tag bit
		auto r = forward_and_receive(m, [](auto & w) { w.back() ^= 0x80; });
		CHECK(r.starts_with("THROW:"));
	}
	{
		tcp_mitm m;
		std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
		m.a.send_raw(make(msg));
		// Shorten the authenticated length, re-split the record
		auto r = forward_and_receive(m, [](auto & w) { w[0] = 4; });
		CHECK(r.starts_with("THROW:"));
	}
	{
		tcp_mitm m;
		std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
		m.a.send_raw(make(msg));
		// Replay the same record twice: second copy must fail
		auto r = forward_and_receive(m, [](auto & w) { auto copy = w; w.insert(w.end(), copy.begin(), copy.end()); });
		CHECK(r.starts_with("THROW:"));
	}
	{
		tcp_mitm m;
		std::vector<uint8_t> m1{'o', 'n', 'e'}, m2{'t', 'w', 'o'};
		m.a.send_raw(make(m1));
		auto w1 = drain(m.a_raw);
		m.a.send_raw(make(m2));
		auto w2 = drain(m.a_raw);
		// Reorder records: must fail
		w2.insert(w2.end(), w1.begin(), w1.end());
		send(m.b_raw, w2.data(), w2.size(), 0);
		bool threw = false;
		try
		{
			recv_one(m.b);
		}
		catch (std::exception &)
		{
			threw = true;
		}
		CHECK(threw);
	}
	{
		tcp_mitm m;
		// Wrong key on the receiver
		std::array<uint8_t, 16> other = key;
		other[0] ^= 1;
		m.b.set_aes_key_and_ivs(other, iv_ab, iv_ba);
		std::vector<uint8_t> msg{'h', 'e', 'l', 'l', 'o'};
		m.a.send_raw(make(msg));
		auto r = forward_and_receive(m, [](auto &) {});
		CHECK(r.starts_with("THROW:"));
	}
}

struct udp_mitm
{
	UDP a, b;
	int a_raw, b_raw;
	udp_mitm()
	{
		int p[2], q[2];
		socketpair(AF_UNIX, SOCK_DGRAM, 0, p);
		socketpair(AF_UNIX, SOCK_DGRAM, 0, q);
		a = UDP(p[0]);
		a_raw = p[1];
		b_raw = q[0];
		b = UDP(q[1]);
		std::span<uint8_t, 16> k{key};
		a.set_aes_key_and_ivs(k, std::span<uint8_t, 8>{iv_ba.data(), 8}, std::span<uint8_t, 8>{iv_ab.data(), 8});
		b.set_aes_key_and_ivs(k, std::span<uint8_t, 8>{iv_ab.data(), 8}, std::span<uint8_t, 8>{iv_ba.data(), 8});
	}
	std::vector<uint8_t> grab()
	{
		std::vector<uint8_t> buf(4096);
		ssize_t n = recv(a_raw, buf.data(), buf.size(), 0);
		buf.resize(n);
		return buf;
	}
	void inject(const std::vector<uint8_t> & d)
	{
		send(b_raw, d.data(), d.size(), 0);
	}
	std::vector<uint8_t> receive()
	{
		pollfd pfd{.fd = (int)b, .events = POLLIN};
		auto p = b.receive_pending();
		if (not p.empty())
			return bytes_of(p);
		if (poll(&pfd, 1, 100) <= 0)
			return {};
		p = b.receive_raw();
		return p.empty() ? std::vector<uint8_t>{} : bytes_of(p);
	}
};

static void test_udp()
{
	udp_mitm m;
	std::vector<uint8_t> msg{'p', 'o', 's', 'e'};

	m.a.send_raw(make(msg));
	auto w0 = m.grab();
	CHECK(w0.size() == 8 + 4 + 16);
	m.inject(w0);
	CHECK(m.receive() == msg);

	// Replay of an accepted packet is dropped
	m.inject(w0);
	CHECK(m.receive().empty());

	// Bit flip in the payload is dropped
	m.a.send_raw(make(msg));
	auto w1 = m.grab();
	auto bad = w1;
	bad[8] ^= 0x01;
	m.inject(bad);
	CHECK(m.receive().empty());
	// ...and does not burn the counter: the genuine packet still gets through
	m.inject(w1);
	CHECK(m.receive() == msg);

	// Tampered counter is dropped
	m.a.send_raw(make(msg));
	auto w2 = m.grab();
	bad = w2;
	bad[0] ^= 0x01;
	m.inject(bad);
	CHECK(m.receive().empty());

	// Truncated packet is dropped
	m.inject(std::vector<uint8_t>(w2.begin(), w2.begin() + 10));
	CHECK(m.receive().empty());

	// Reordering inside the window is accepted
	std::vector<serialization_packet> many;
	std::vector<std::vector<uint8_t>> msgs;
	for (int i = 0; i < 5; ++i)
		msgs.push_back(payload(100, i));
	for (auto & x: msgs)
		many.push_back(make(x));
	m.a.send_many_raw(many);
	std::vector<std::vector<uint8_t>> wires;
	for (int i = 0; i < 5; ++i)
		wires.push_back(m.grab());
	for (int i = 4; i >= 0; --i)
		m.inject(wires[i]);
	std::vector<std::vector<uint8_t>> got;
	for (int i = 0; i < 5; ++i)
		got.push_back(m.receive());
	int matched = 0;
	for (auto & g: got)
		for (auto & x: msgs)
			matched += g == x;
	CHECK(matched == 5);

	// A batch mixing good and forged datagrams keeps only the good ones
	m.a.send_raw(make(msg));
	auto g1 = m.grab();
	m.a.send_raw(make(msg));
	auto g2 = m.grab();
	bad = g1;
	bad[9] ^= 0xff;
	m.inject(bad);
	m.inject(g2);
	m.inject(bad);
	CHECK(m.receive() == msg);
	CHECK(m.receive().empty());

	// Packets older than the replay window are dropped
	for (int i = 0; i < 4100; ++i)
	{
		m.a.send_raw(make(msg));
		auto w = m.grab();
		if (i == 4099)
			m.inject(w);
	}
	CHECK(m.receive() == msg);
	m.inject(g1); // never delivered, but now > 4096 behind
	CHECK(m.receive().empty());

	// Advancing the window clears the slots it skips: a packet whose slot was last
	// used 4096 counters earlier is still accepted
	std::vector<std::vector<uint8_t>> seq;
	for (int i = 0; i < 4098; ++i)
	{
		m.a.send_raw(make(msg));
		seq.push_back(m.grab());
	}
	m.inject(seq[0]);
	CHECK(m.receive() == msg);
	m.inject(seq[4095]);
	CHECK(m.receive() == msg);
	m.inject(seq[4097]);
	CHECK(m.receive() == msg);
	m.inject(seq[4096]);
	CHECK(m.receive() == msg);
}

// handshake_gate: an idle or partial connection never blocks a peer that sends a full first record
static int gate_connect(int port)
{
	int c = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a{};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = htons(port);
	if (connect(c, (sockaddr *)&a, sizeof(a)) < 0)
	{
		close(c);
		return -1;
	}
	return c;
}

static void send_record(int fd, uint32_t size, size_t sent_payload)
{
	std::vector<uint8_t> buf(sizeof(size) + sent_payload, 0x42);
	memcpy(buf.data(), &size, sizeof(size));
	CHECK(send(fd, buf.data(), buf.size(), 0) == ssize_t(buf.size()));
}

static std::optional<TCP> gate_poll(handshake_gate & gate, std::chrono::steady_clock::time_point now)
{
	// Give loopback a moment to deliver connects and data
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	return gate.poll(now);
}

static size_t open_fds()
{
	auto it = std::filesystem::directory_iterator("/proc/self/fd");
	return std::distance(begin(it), end(it));
}

static void test_handshake_gate()
{
	handshake_gate gate(0);
	sockaddr_in6 a{};
	socklen_t len = sizeof(a);
	getsockname(gate.get_fd(), (sockaddr *)&a, &len);
	int port = ntohs(a.sin6_port);
	auto t0 = std::chrono::steady_clock::now();

	// An idle connection is held back, and does not stop a later complete one from getting through
	int idle = gate_connect(port);
	CHECK(idle >= 0);
	CHECK(not gate_poll(gate, t0));
	CHECK(gate.pending_count() == 1);

	int partial = gate_connect(port);
	send_record(partial, 100, 50); // header plus half the payload
	CHECK(not gate_poll(gate, t0));
	CHECK(gate.pending_count() == 2);

	int good = gate_connect(port);
	send_record(good, 100, 100);
	auto handed = gate_poll(gate, t0);
	CHECK(handed.has_value());
	CHECK(gate.pending_count() == 2);
	if (handed)
	{
		// The record is still unread, so the handshake sees it from the first byte
		CHECK(bytes_of(recv_one(*handed)) == std::vector<uint8_t>(100, 0x42));
	}

	// Several more connects (more than the old backlog of 1) are all accepted at once
	std::vector<int> extra;
	for (int i = 0; i < 4; ++i)
		extra.push_back(gate_connect(port));
	CHECK(std::ranges::all_of(extra, [](int fd) { return fd >= 0; }));
	CHECK(not gate_poll(gate, t0));
	CHECK(gate.pending_count() == 6);

	// Invalid sizes and closed peers are dropped at once
	send_record(extra[0], 0, 0);
	send_record(extra[1], handshake_gate::max_first_record + 1, 0);
	close(extra[2]);
	extra[2] = -1;
	CHECK(not gate_poll(gate, t0));
	CHECK(gate.pending_count() == 3);

	// Past the deadline, idle and partial peers are dropped
	CHECK(not gate_poll(gate, t0 + handshake_gate::first_record_timeout + std::chrono::milliseconds(1)));
	CHECK(gate.pending_count() == 0);
	char c;
	CHECK(recv(idle, &c, 1, 0) == 0); // the server closed it

	// When full, the oldest pending connection makes room for the newest
	std::vector<int> flood;
	for (size_t i = 0; i < handshake_gate::max_pending + 2; ++i)
	{
		flood.push_back(gate_connect(port));
		gate_poll(gate, t0);
	}
	CHECK(gate.pending_count() == handshake_gate::max_pending);
	// The two oldest were evicted (closed by the server), the newest was kept
	CHECK(recv(flood[0], &c, 1, MSG_DONTWAIT) == 0);
	CHECK(recv(flood[1], &c, 1, MSG_DONTWAIT) == 0);
	CHECK(recv(flood[2], &c, 1, MSG_DONTWAIT) < 0 and errno == EAGAIN);
	send_record(flood.back(), 8, 8);
	CHECK(gate_poll(gate, t0).has_value());

	// A burst of idle connects landing between two polls does not evict a peer that is ready
	auto t1 = t0 + 2 * handshake_gate::first_record_timeout;
	CHECK(not gate_poll(gate, t1)); // expire the flood
	CHECK(gate.pending_count() == 0);
	size_t fds_before = open_fds();
	int ready = gate_connect(port);
	send_record(ready, 8, 8);
	std::vector<int> burst;
	// Exactly fills the kernel queue (backlog + 1): more would block in connect
	for (size_t i = 0; i < handshake_gate::max_pending; ++i)
		burst.push_back(gate_connect(port));
	auto got = gate_poll(gate, t1);
	CHECK(got.has_value());
	if (got)
		CHECK(bytes_of(recv_one(*got)) == std::vector<uint8_t>(8, 0x42));
	for (int fd: burst)
		close(fd);
	close(ready);
	got.reset();
	gate_poll(gate, t1 + 2 * handshake_gate::first_record_timeout); // drain and expire the burst
	CHECK(gate.pending_count() == 0);
	CHECK(open_fds() == fds_before); // no descriptor leaked on the full-gate handoff path

	for (int fd: extra)
		if (fd >= 0)
			close(fd);
	for (int fd: flood)
		close(fd);
	close(idle);
	close(partial);
	close(good);
}

int main()
{
	test_tcp();
	test_udp();
	test_handshake_gate();
	printf(failures ? "FAILED: %d\n" : "ALL PASSED\n", failures);
	return failures != 0;
}
