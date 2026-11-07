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

// Tests the server-authentication pieces of the handshake: identity key storage, the headset's
// trusted server list (and forgetting it), the server_key_error state sent when the identity key
// cannot be loaded, session key derivation and the PIN check binding.

#include "handshake_identity.h"
#include "identity.h"
#include "secrets.h"
#include "smp.h"
#include "wivrn_sockets.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <variant>

#define CHECK(x)                                                                            \
	do                                                                                  \
	{                                                                                   \
		if (not(x))                                                                 \
		{                                                                           \
			std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED " #x << "\n"; \
			std::exit(1);                                                       \
		}                                                                           \
	} while (0)

namespace
{
bool same_keys(const secrets & a, const secrets & b)
{
	return a.control_key == b.control_key and a.stream_key == b.stream_key and
	       a.control_iv_to_headset == b.control_iv_to_headset;
}

crypto::key public_part(const crypto::key & k)
{
	return crypto::key::from_public_key(k.public_key());
}

// Run the 4-message SMP exchange with the headset as alice and the server as bob
bool smp_match(const std::string & headset_secret, const std::string & server_secret)
{
	crypto::smp headset, server;
	auto msg1 = headset.step1(headset_secret);
	auto msg2 = server.step2(msg1, server_secret);
	auto msg3 = headset.step3(msg2);
	auto [msg4, server_match] = server.step4(msg3);
	bool headset_match = headset.step5(msg4);
	CHECK(server_match == headset_match);
	return headset_match;
}

void test_identity_key(const std::filesystem::path & dir)
{
	auto path = dir / "sub" / "server_key.pem";

	crypto::key created = wivrn::load_or_create_identity_key(path);
	struct stat st; // filled by stat()
	CHECK(::stat(path.c_str(), &st) == 0);
	CHECK((st.st_mode & 0777) == 0600);

	// Reloading returns the same key
	crypto::key loaded = wivrn::load_or_create_identity_key(path);
	CHECK(created.raw_public_key() == loaded.raw_public_key());
	CHECK(created.raw_public_key().size() == 56);

	// A corrupted key file is an error, never silently replaced
	std::ofstream{path} << "garbage";
	bool threw = false;
	try
	{
		wivrn::load_or_create_identity_key(path);
	}
	catch (std::exception &)
	{
		threw = true;
	}
	CHECK(threw);
	CHECK(std::filesystem::file_size(path) == 7);

	// A key of the wrong type is rejected
	std::ofstream{path} << crypto::key::generate_x25519_keypair().private_key();
	threw = false;
	try
	{
		wivrn::load_or_create_identity_key(path);
	}
	catch (std::exception &)
	{
		threw = true;
	}
	CHECK(threw);
}

void test_identity_key_race(const std::filesystem::path & dir)
{
	// Concurrent first use: every caller gets the key that ends up on disk
	for (int round = 0; round < 50; round++)
	{
		auto path = dir / ("race" + std::to_string(round)) / "server_key.pem";
		std::vector<uint8_t> a, b;
		std::thread t1{[&] { a = wivrn::load_or_create_identity_key(path).raw_public_key(); }};
		std::thread t2{[&] { b = wivrn::load_or_create_identity_key(path).raw_public_key(); }};
		t1.join();
		t2.join();
		auto stored = wivrn::load_or_create_identity_key(path).raw_public_key();
		CHECK(a == stored);
		CHECK(b == stored);
	}

	// A dangling symlink is an error naming the file, not an endless retry nor a replaced link
	{
		auto link_path = dir / "dangling" / "server_key.pem";
		std::filesystem::create_directories(link_path.parent_path());
		std::filesystem::create_symlink(dir / "dangling" / "missing" / "key.pem", link_path);
		bool threw = false;
		try
		{
			wivrn::load_or_create_identity_key(link_path);
		}
		catch (std::exception &)
		{
			threw = true;
		}
		CHECK(threw);
		CHECK(std::filesystem::is_symlink(link_path));
	}

	// A stale world-readable temporary file does not leak its mode to the key
	auto path = dir / "stale" / "server_key.pem";
	std::filesystem::create_directories(path.parent_path());
	auto stale = path;
	stale += ".new";
	std::ofstream{stale} << "stale";
	::chmod(stale.c_str(), 0644);
	wivrn::load_or_create_identity_key(path);
	struct stat st; // filled by stat()
	CHECK(::stat(path.c_str(), &st) == 0);
	CHECK((st.st_mode & 0777) == 0600);
}

// Connected loopback TCP socket pair: {accepted, connecting}
std::pair<int, int> tcp_pair()
{
	int listener = ::socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t len = sizeof(addr);
	CHECK(::bind(listener, (sockaddr *)&addr, sizeof(addr)) == 0);
	CHECK(::listen(listener, 1) == 0);
	CHECK(::getsockname(listener, (sockaddr *)&addr, &len) == 0);

	int client = ::socket(AF_INET, SOCK_STREAM, 0);
	CHECK(::connect(client, (sockaddr *)&addr, sizeof(addr)) == 0);
	int server = ::accept(listener, nullptr, nullptr);
	CHECK(server >= 0);
	::close(listener);
	return {server, client};
}

void test_no_plaintext_before_key_change()
{
	// Bytes received before the keys are set must not be accepted afterwards as if decrypted
	auto [receiver_fd, sender_fd] = tcp_pair();
	wivrn::TCP receiver{receiver_fd};

	const uint8_t partial[] = {8, 0, 0, 0, 1, 2}; // header of an 8-byte packet and part of it
	CHECK(::write(sender_fd, partial, sizeof(partial)) == (ssize_t)sizeof(partial));
	pollfd pfd{.fd = receiver_fd, .events = POLLIN};
	CHECK(::poll(&pfd, 1, 1000) == 1);
	CHECK(receiver.receive_raw().empty()); // incomplete packet stays buffered

	std::array<uint8_t, 16> key{}, iv{};
	bool threw = false;
	try
	{
		receiver.set_aes_key_and_ivs(key, iv, iv);
	}
	catch (std::exception &)
	{
		threw = true;
	}
	CHECK(threw);

	// With nothing pending, setting the keys works
	auto [idle_fd, idle_peer] = tcp_pair();
	wivrn::TCP idle{idle_fd};
	idle.set_aes_key_and_ivs(key, iv, iv);
	::close(sender_fd);
	::close(idle_peer);
}

void test_trusted_keys(const std::filesystem::path & dir)
{
	auto path = dir / "trusted_servers";
	crypto::key a = crypto::key::generate_x448_keypair();
	crypto::key b = crypto::key::generate_x448_keypair();

	CHECK(not wivrn::is_trusted_key(path, a)); // missing file

	wivrn::add_trusted_key(path, a);
	CHECK(wivrn::is_trusted_key(path, a));
	CHECK(wivrn::is_trusted_key(path, public_part(a))); // matched by public key only
	CHECK(not wivrn::is_trusted_key(path, b));

	wivrn::add_trusted_key(path, a); // no duplicate
	wivrn::add_trusted_key(path, b);
	CHECK(wivrn::is_trusted_key(path, b));

	std::ifstream f{path};
	int lines = 0;
	for (std::string line; std::getline(f, line);)
		lines++;
	CHECK(lines == 2);

	struct stat st; // filled by stat()
	CHECK(::stat(path.c_str(), &st) == 0);
	CHECK((st.st_mode & 0777) == 0600);
}

void test_forget_trusted_keys(const std::filesystem::path & dir)
{
	auto path = dir / "forget" / "trusted_servers";
	std::filesystem::create_directories(path.parent_path());
	crypto::key a = crypto::key::generate_x448_keypair();
	crypto::key b = crypto::key::generate_x448_keypair();
	wivrn::add_trusted_key(path, a);
	wivrn::add_trusted_key(path, b);

	std::error_code ec;
	wivrn::forget_trusted_keys(path, ec);
	CHECK(not ec);
	// The headset refuses client_already_paired from a server it no longer trusts
	CHECK(not wivrn::is_trusted_key(path, a));
	CHECK(not wivrn::is_trusted_key(path, b));

	// Forgetting with nothing stored is not an error
	wivrn::forget_trusted_keys(path, ec);
	CHECK(not ec);

	// Pairing again with the PIN trusts the server again
	wivrn::add_trusted_key(path, a);
	CHECK(wivrn::is_trusted_key(path, a));
	CHECK(not wivrn::is_trusted_key(path, b));
}

// Receive one packet on a blocking-free socket, waiting up to 1s
template <typename Socket>
auto receive_one(Socket & socket)
{
	for (int i = 0; i < 100; i++)
	{
		if (auto packet = socket.receive())
			return *packet;
		pollfd pfd{.fd = socket.get_fd(), .events = POLLIN};
		::poll(&pfd, 1, 10);
	}
	CHECK(false);
	__builtin_unreachable();
}

void test_identity_key_error(const std::filesystem::path & dir)
{
	using wivrn::to_headset::crypto_handshake;
	auto [server_fd, headset_fd] = tcp_pair();
	wivrn::typed_socket<wivrn::TCP, wivrn::from_headset::packets, wivrn::to_headset::packets> server{server_fd};
	wivrn::typed_socket<wivrn::TCP, wivrn::to_headset::packets, wivrn::from_headset::packets> headset{headset_fd};
	auto send = [&](auto && packet) { server.send(std::forward<decltype(packet)>(packet)); };

	auto path = dir / "key_error" / "server_key.pem";
	auto load = [&] { return wivrn::load_or_create_identity_key(path); };

	// A loadable key is returned and nothing is sent: the caller sends the real handshake
	crypto::key key = wivrn::identity_key_or_notify(load, send);
	CHECK(key.raw_public_key() == wivrn::load_or_create_identity_key(path).raw_public_key());
	pollfd pfd{.fd = headset_fd, .events = POLLIN};
	CHECK(::poll(&pfd, 1, 100) == 0);

	// A corrupted key file: the headset is told why before the server gives up
	std::ofstream{path} << "garbage";
	bool threw = false;
	try
	{
		wivrn::identity_key_or_notify(load, send);
	}
	catch (std::exception &)
	{
		threw = true;
	}
	CHECK(threw);
	CHECK(std::filesystem::file_size(path) == 7); // never replaced

	auto packet = receive_one(headset);
	CHECK(std::holds_alternative<crypto_handshake>(packet));
	CHECK(std::get<crypto_handshake>(packet).state == crypto_handshake::crypto_state::server_key_error);
}

void test_session_keys()
{
	crypto::key headset = crypto::key::generate_x448_keypair();
	crypto::key identity = crypto::key::generate_x448_keypair();
	crypto::key ephemeral = crypto::key::generate_x448_keypair();

	crypto::key headset_pub = public_part(headset);
	crypto::key identity_pub = public_part(identity);
	crypto::key ephemeral_pub = public_part(ephemeral);

	auto server_side = secrets::server(ephemeral, identity, headset_pub, "000000");
	auto headset_side = secrets::headset(headset, ephemeral_pub, identity_pub, "000000");
	CHECK(same_keys(server_side, headset_side));

	// Keys depend on the key exchange, not only on the PIN: a new ephemeral key gives new keys
	crypto::key ephemeral2 = crypto::key::generate_x448_keypair();
	crypto::key ephemeral2_pub = public_part(ephemeral2);
	CHECK(not same_keys(headset_side, secrets::headset(headset, ephemeral2_pub, identity_pub, "000000")));

	// A PIN mismatch gives different keys
	CHECK(not same_keys(server_side, secrets::headset(headset, ephemeral_pub, identity_pub, "123456")));

	// An impostor that only knows the real server's public identity key cannot derive the keys:
	// it must use its own identity private key, and the headset uses the pinned public key.
	crypto::key rogue_identity = crypto::key::generate_x448_keypair();
	crypto::key rogue_ephemeral = crypto::key::generate_x448_keypair();
	crypto::key rogue_ephemeral_pub = public_part(rogue_ephemeral);
	auto rogue_side = secrets::server(rogue_ephemeral, rogue_identity, headset_pub, "000000");
	auto victim_side = secrets::headset(headset, rogue_ephemeral_pub, identity_pub, "000000");
	CHECK(not same_keys(rogue_side, victim_side));
}

void test_pin_check_binding()
{
	crypto::key headset = crypto::key::generate_x448_keypair();
	crypto::key identity = crypto::key::generate_x448_keypair();
	crypto::key rogue_identity = crypto::key::generate_x448_keypair();

	CHECK(pin_check_secret("123456", identity, headset) == pin_check_secret("123456", public_part(identity), public_part(headset)));

	// Honest pairing: same PIN, same keys
	CHECK(smp_match(pin_check_secret("123456", identity, headset), pin_check_secret("123456", identity, headset)));

	// Wrong PIN
	CHECK(not smp_match(pin_check_secret("123456", identity, headset), pin_check_secret("654321", identity, headset)));

	// A relay that shows its own identity key to the headset and forwards the PIN check to the
	// real server: the PIN is right but the keys differ, so the check fails.
	CHECK(not smp_match(pin_check_secret("123456", rogue_identity, headset), pin_check_secret("123456", identity, headset)));
}
} // namespace

// The headset shows this fingerprint so its user can check it against fenrir's headset
// confirmation page. The expected value was computed outside WiVRn the way fenrir's
// headsetFingerprint does: SHA-256 of the base64-decoded PEM body, first 8 bytes, hex in 4s.
void test_public_key_fingerprint()
{
	// Throwaway X448 key, only used here
	const char * private_pem =
	        "-----BEGIN PRIVATE KEY-----\n"
	        "MEYCAQAwBQYDK2VvBDoEOFyb3rBN0EGyY3KPyuj/1O/pZlm4+iSZBg9GDM2JGJ4D\n"
	        "R6xokOoXB+sBkysWiJkWnI/w8t1mPGXn\n"
	        "-----END PRIVATE KEY-----\n";
	const char * public_pem =
	        "-----BEGIN PUBLIC KEY-----\n"
	        "MEIwBQYDK2VvAzkAZKjZa0UJsTolyGPneaMxuwriK/FGJCq5rxeuJ14hq3LkELZK\n"
	        "rg1AX2vFs8HZOdljZfTR2fU6jww=\n"
	        "-----END PUBLIC KEY-----\n";
	const std::string expected = "9b0c 4b20 a4ef 1a4a";

	auto priv = crypto::key::from_private_key(private_pem);
	CHECK(priv.public_key_fingerprint() == expected);
	CHECK(crypto::key::from_public_key(public_pem).public_key_fingerprint() == expected);
	CHECK(priv.public_key() == public_pem);

	auto other = crypto::key::generate_x448_keypair();
	CHECK(other.public_key_fingerprint() != expected);
	CHECK(other.public_key_fingerprint().size() == 19);
}

int main()
{
	char tmpl[] = "/tmp/wivrn-handshake-test-XXXXXX";
	CHECK(::mkdtemp(tmpl) != nullptr);
	std::filesystem::path dir = tmpl;

	test_identity_key(dir);
	test_identity_key_race(dir);
	test_no_plaintext_before_key_change();
	test_trusted_keys(dir);
	test_forget_trusted_keys(dir);
	test_identity_key_error(dir);
	test_session_keys();
	test_pin_check_binding();
	test_public_key_fingerprint();

	std::filesystem::remove_all(dir);
	std::cout << "All handshake crypto tests passed\n";
	return 0;
}
