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
// trusted server list, session key derivation and the PIN check binding.

#include "identity.h"
#include "secrets.h"
#include "smp.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

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
	struct stat st
	{};
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

	struct stat st
	{};
	CHECK(::stat(path.c_str(), &st) == 0);
	CHECK((st.st_mode & 0777) == 0600);
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

int main()
{
	char tmpl[] = "/tmp/wivrn-handshake-test-XXXXXX";
	CHECK(::mkdtemp(tmpl) != nullptr);
	std::filesystem::path dir = tmpl;

	test_identity_key(dir);
	test_trusted_keys(dir);
	test_session_keys();
	test_pin_check_binding();

	std::filesystem::remove_all(dir);
	std::cout << "All handshake crypto tests passed\n";
	return 0;
}
