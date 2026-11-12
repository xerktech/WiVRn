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

// Standalone tests of the fenrir front door client: see .github/workflows/Sockets-UT.yml

#include "../fenrir.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <unistd.h>

namespace
{
int failures = 0;

#define CHECK(cond)                                                                         \
	do                                                                                  \
	{                                                                                   \
		if (not(cond))                                                              \
		{                                                                           \
			std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED " #cond "\n"; \
			++failures;                                                         \
		}                                                                           \
	} while (0)

template <typename F>
bool throws(F && f)
{
	try
	{
		f();
		return false;
	}
	catch (std::exception &)
	{
		return true;
	}
}

std::array<uint8_t, 32> fill(uint8_t start, int step)
{
	std::array<uint8_t, 32> a;
	for (int i = 0; i < 32; ++i)
		a[i] = start + step * i;
	return a;
}

void test_pairing_code()
{
	std::array<uint8_t, 32> z{};
	// fenrir pkg/moonlight/vrdoor_test.go fixedVRCode: all-zero inputs, empty WiVRn key
	CHECK(fenrir::pairing_code(z, z, "", z, z) == "22350317");

	// Distinct inputs, computed independently from fenrir docs/vr-native-session.md step 3
	auto sk = fill(0, 1), ck = fill(32, 1);
	std::array<uint8_t, 32> sn, hn;
	sn.fill(0xaa);
	hn.fill(0x55);
	CHECK(fenrir::pairing_code(sk, ck, "MEIwBQYDK2VvAzkAabc=", sn, hn) == "22152164");

	// Every input changes it
	auto base = fenrir::pairing_code(sk, ck, "key", sn, hn);
	auto flip = [](std::array<uint8_t, 32> a) { a[0] ^= 1; return a; };
	CHECK(fenrir::pairing_code(flip(sk), ck, "key", sn, hn) != base);
	CHECK(fenrir::pairing_code(sk, flip(ck), "key", sn, hn) != base);
	CHECK(fenrir::pairing_code(sk, ck, "kez", sn, hn) != base);
	CHECK(fenrir::pairing_code(sk, ck, "key", flip(sn), hn) != base);
	CHECK(fenrir::pairing_code(sk, ck, "key", sn, flip(hn)) != base);

	CHECK(fenrir::format_code("01234567") == "0123 4567");
}

void test_hex()
{
	CHECK(fenrir::to_hex(std::vector<uint8_t>{0x00, 0xab, 0xff}) == "00abff");
	CHECK(fenrir::from_hex("00ABff") == (std::vector<uint8_t>{0x00, 0xab, 0xff}));
	CHECK(not fenrir::from_hex("abc"));
	CHECK(not fenrir::from_hex("zz"));
}

void test_tls_identity()
{
	auto id = fenrir::make_tls_identity();
	CHECK(id.key.starts_with("-----BEGIN PRIVATE KEY-----"));
	CHECK(id.cert.starts_with("-----BEGIN CERTIFICATE-----"));

	// The certificate's key hash is SHA-256 of the private key's SubjectPublicKeyInfo
	BIO * bio = BIO_new_mem_buf(id.key.data(), id.key.size());
	EVP_PKEY * key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	CHECK(key);
	unsigned char * der = nullptr;
	int len = i2d_PUBKEY(key, &der);
	auto expected = fenrir::sha256({reinterpret_cast<char *>(der), (size_t)len});
	OPENSSL_free(der);
	EVP_PKEY_free(key);
	CHECK(fenrir::certificate_key_sha256(id.cert) == expected);

	// Two identities never share a key
	CHECK(fenrir::certificate_key_sha256(fenrir::make_tls_identity().cert) != expected);
	CHECK(throws([] { fenrir::certificate_key_sha256("garbage"); }));
}

void test_wivrn_key_body()
{
	CHECK(fenrir::wivrn_key_body("-----BEGIN PUBLIC KEY-----\nMEIwBQYDK2VvAzkA\r\nabcd\n-----END PUBLIC KEY-----\n") == "MEIwBQYDK2VvAzkAabcd");
}

void test_parse()
{
	auto apps = fenrir::parse_apps(R"({"apps":[{"id":"ac","title":"Assetto Corsa","cover":"/vr/v1/apps/ac/cover"},{"id":"x"}]})");
	CHECK(apps.size() == 2);
	CHECK(apps[0].title == "Assetto Corsa" and apps[0].cover == "/vr/v1/apps/ac/cover");
	CHECK(apps[1].title == "x" and apps[1].cover.empty());
	CHECK(throws([] { fenrir::parse_apps(R"({"apps":[{"title":"no id"}]})"); }));

	std::string key(112, 'a');
	auto s = fenrir::parse_session(R"({"state":"ready","app":"ac","title":"AC","host":"10.0.0.4","port":21000,"serverKey":")" + key + R"(","headsetConnected":false})");
	CHECK(s.state == "ready" and s.host == "10.0.0.4" and s.port == 21000 and s.server_key == key);

	auto starting = fenrir::parse_session(R"({"state":"starting","headsetConnected":false,"message":"pulling"})");
	CHECK(starting.state == "starting" and starting.message == "pulling" and starting.port == 0);

	// Ready without what the stream needs to be pinned is refused
	CHECK(throws([] { fenrir::parse_session(R"({"state":"ready","host":"h","port":1,"headsetConnected":false})"); }));
	CHECK(throws([] { fenrir::parse_session(R"({"state":"ready","host":"h","port":1,"serverKey":"abcd","headsetConnected":false})"); }));
	CHECK(throws([&] { fenrir::parse_session(R"({"state":"ready","port":1,"serverKey":")" + key + R"(","headsetConnected":false})"); }));
	CHECK(throws([] { fenrir::parse_session(R"({"state":"none","port":70000,"headsetConnected":false})"); }));

	CHECK(fenrir::parse_error(R"({"error":"this headset is not paired"})") == "this headset is not paired");
	CHECK(fenrir::parse_error("<html>").empty());
}

std::string read(const std::filesystem::path & p)
{
	std::ifstream f{p};
	return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void test_store(const std::filesystem::path & dir)
{
	auto path = dir / "fenrir.json";
	std::filesystem::remove(path);

	// Missing: empty
	CHECK(fenrir::store::load(path).servers.empty());

	auto id = fenrir::make_tls_identity();
	fenrir::store s;
	s.servers.push_back({.id = "a1", .name = "fenrir \"home\"", .host = "fe80::1", .port = 47990, .tls_key = id.key, .tls_cert = id.cert, .server_key_sha256 = std::string(64, 'b'), .paired = true});
	s.servers.push_back({.id = "b2", .name = "new", .host = "h", .port = 1, .tls_key = id.key, .tls_cert = id.cert});
	s.save(path);
	CHECK((std::filesystem::status(path).permissions() & (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) == std::filesystem::perms::none);

	auto l = fenrir::store::load(path);
	CHECK(l.servers.size() == 2);
	CHECK(l.servers[0].name == "fenrir \"home\"" and l.servers[0].host == "fe80::1" and l.servers[0].port == 47990);
	CHECK(l.servers[0].tls_key == id.key and l.servers[0].tls_cert == id.cert and l.servers[0].paired);
	CHECK(l.servers[0].server_key_sha256 == std::string(64, 'b'));
	CHECK(not l.servers[1].paired and l.servers[1].server_key_sha256.empty());

	// A bad entry is kept as it was, and written back
	std::string json = read(path);
	json.insert(json.find('[') + 1, R"({"id":"bad","port":99999},)");
	std::ofstream{path} << json;
	l = fenrir::store::load(path);
	CHECK(l.servers.size() == 2 and l.unparsed.size() == 1);
	l.save(path);
	CHECK(read(path).find(R"("id":"bad")") != std::string::npos);

	// Paired without a pinned key is not usable
	std::ofstream{path} << R"({"servers":[{"id":"c","name":"c","host":"h","port":1,"tls_key":"k","tls_cert":"c","server_key_sha256":"","paired":true}]})";
	l = fenrir::store::load(path);
	CHECK(l.servers.empty() and l.unparsed.size() == 1);

	// A damaged file is moved aside, never overwritten
	for (auto & e: std::filesystem::directory_iterator(dir))
		if (e.path().filename().string().starts_with("fenrir.json.bad-"))
			std::filesystem::remove(e.path());
	std::ofstream{path} << R"({"servers":[{"id":)";
	l = fenrir::store::load(path);
	CHECK(l.servers.empty());
	CHECK(not std::filesystem::exists(path));
	int backups = 0;
	for (auto & e: std::filesystem::directory_iterator(dir))
		if (e.path().filename().string().starts_with("fenrir.json.bad-"))
		{
			++backups;
			CHECK(read(e.path()) == R"({"servers":[{"id":)");
		}
	CHECK(backups == 1);
}
} // namespace

int main()
{
	auto dir = std::filesystem::temp_directory_path() / ("fenrir_ut." + std::to_string(::getpid()));
	std::filesystem::create_directories(dir);

	test_pairing_code();
	test_hex();
	test_tls_identity();
	test_wivrn_key_body();
	test_parse();
	test_store(dir);

	std::filesystem::remove_all(dir);
	if (failures)
	{
		std::cerr << failures << " failure(s)\n";
		return 1;
	}
	std::cout << "fenrir_ut: all tests passed\n";
	return 0;
}
