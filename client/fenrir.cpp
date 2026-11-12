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

#include "fenrir.h"

#include "identity.h"
#include "utils/json_string.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <curl/curl.h>
#include <memory>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <simdjson.h>
#include <sstream>

namespace fenrir
{
namespace
{
template <typename T, void (*F)(T *)>
struct deleter
{
	void operator()(T * p) const
	{
		F(p);
	}
};
void bio_free(BIO * b)
{
	BIO_free(b);
}
using bio_ptr = std::unique_ptr<BIO, deleter<BIO, bio_free>>;
using x509_ptr = std::unique_ptr<X509, deleter<X509, X509_free>>;
using pkey_ptr = std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY, EVP_PKEY_free>>;

std::string bio_string(BIO * bio)
{
	char * data;
	long len = BIO_get_mem_data(bio, &data);
	return {data, (size_t)len};
}

x509_ptr parse_certificate(std::string_view pem)
{
	bio_ptr bio{BIO_new_mem_buf(pem.data(), (int)pem.size())};
	if (not bio)
		throw std::runtime_error("BIO_new_mem_buf failed");
	x509_ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	if (not cert)
		throw std::runtime_error("not a PEM certificate");
	return cert;
}

std::string base64(std::span<const uint8_t> data)
{
	std::string out(4 * ((data.size() + 2) / 3), '\0');
	int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data.data(), (int)data.size());
	out.resize(n);
	return out;
}

std::array<uint8_t, 32> to_array(const std::vector<uint8_t> & v)
{
	std::array<uint8_t, 32> a{};
	if (v.size() != a.size())
		throw std::invalid_argument("expected 32 bytes");
	std::copy(v.begin(), v.end(), a.begin());
	return a;
}

std::array<uint8_t, 32> parse_hex32(std::string_view hex)
{
	auto v = from_hex(hex);
	if (not v or v->size() != 32)
		throw std::runtime_error("expected 64 hex digits");
	return to_array(*v);
}

std::string get_string(simdjson::dom::object & o, const char * key)
{
	std::string_view v;
	if (o[key].get(v) != simdjson::SUCCESS)
		return {};
	return std::string{v};
}
} // namespace

std::string to_hex(std::span<const uint8_t> bytes)
{
	std::string hex;
	hex.reserve(bytes.size() * 2);
	for (uint8_t byte: bytes)
	{
		hex += "0123456789abcdef"[byte >> 4];
		hex += "0123456789abcdef"[byte & 0xf];
	}
	return hex;
}

std::optional<std::vector<uint8_t>> from_hex(std::string_view hex)
{
	if (hex.size() % 2)
		return std::nullopt;
	auto digit = [](char c) -> int {
		if (c >= '0' and c <= '9')
			return c - '0';
		if (c >= 'a' and c <= 'f')
			return c - 'a' + 10;
		if (c >= 'A' and c <= 'F')
			return c - 'A' + 10;
		return -1;
	};
	std::vector<uint8_t> out;
	out.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2)
	{
		int hi = digit(hex[i]), lo = digit(hex[i + 1]);
		if (hi < 0 or lo < 0)
			return std::nullopt;
		out.push_back(hi << 4 | lo);
	}
	return out;
}

std::array<uint8_t, 32> sha256(std::string_view data)
{
	std::array<uint8_t, 32> out;
	unsigned int len = out.size();
	if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1 or len != out.size())
		throw std::runtime_error("SHA-256 failed");
	return out;
}

std::array<uint8_t, 32> random_nonce()
{
	std::array<uint8_t, 32> out;
	if (RAND_bytes(out.data(), out.size()) != 1)
		throw std::runtime_error("RAND_bytes failed");
	return out;
}

std::string random_id()
{
	auto n = random_nonce();
	return to_hex(std::span{n}.first(8));
}

std::array<uint8_t, 32> certificate_key_sha256(std::string_view pem)
{
	auto cert = parse_certificate(pem);
	unsigned char * der = nullptr;
	int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert.get()), &der);
	if (len <= 0)
		throw std::runtime_error("cannot encode the certificate's public key");
	auto hash = sha256({reinterpret_cast<const char *>(der), (size_t)len});
	OPENSSL_free(der);
	return hash;
}

tls_identity make_tls_identity()
{
	pkey_ptr key{EVP_EC_gen("P-256")};
	if (not key)
		throw std::runtime_error("cannot generate the TLS key");

	x509_ptr cert{X509_new()};
	if (not cert)
		throw std::runtime_error("X509_new failed");

	auto serial = random_nonce();
	serial[0] &= 0x7f; // positive
	std::unique_ptr<BIGNUM, deleter<BIGNUM, BN_free>> bn{BN_bin2bn(serial.data(), 16, nullptr)};
	if (not bn or not BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert.get())))
		throw std::runtime_error("cannot set the certificate serial");

	X509_set_version(cert.get(), 2);
	// fenrir names the headset by the key alone: the dates only need to be valid for a long time
	X509_gmtime_adj(X509_getm_notBefore(cert.get()), -24 * 3600);
	X509_gmtime_adj(X509_getm_notAfter(cert.get()), 100L * 365 * 24 * 3600);
	X509_NAME * subject = X509_get_subject_name(cert.get());
	X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("WiVRn headset"), -1, -1, 0);
	X509_set_issuer_name(cert.get(), subject);
	if (X509_set_pubkey(cert.get(), key.get()) != 1 or X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0)
		throw std::runtime_error("cannot sign the TLS certificate");

	bio_ptr key_bio{BIO_new(BIO_s_mem())};
	bio_ptr cert_bio{BIO_new(BIO_s_mem())};
	if (not key_bio or not cert_bio or
	    PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1 or
	    PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1)
		throw std::runtime_error("cannot encode the TLS identity");

	return {.key = bio_string(key_bio.get()), .cert = bio_string(cert_bio.get())};
}

std::string wivrn_key_body(std::string_view pem)
{
	std::string out;
	std::istringstream lines{std::string{pem}};
	for (std::string line; std::getline(lines, line);)
	{
		if (not line.empty() and line.back() == '\r')
			line.pop_back();
		if (line.empty() or line.starts_with("-----"))
			continue;
		out += line;
	}
	return out;
}

std::string pairing_code(
        const std::array<uint8_t, 32> & server_key,
        const std::array<uint8_t, 32> & client_key,
        std::string_view wivrn_key,
        const std::array<uint8_t, 32> & server_nonce,
        const std::array<uint8_t, 32> & headset_nonce)
{
	std::string msg = "direwolf-vr-pair-v1";
	msg += '\0';
	auto append = [&](std::span<const uint8_t> b) { msg.append(reinterpret_cast<const char *>(b.data()), b.size()); };
	append(server_key);
	append(client_key);
	append(sha256(wivrn_key));
	append(server_nonce);
	append(headset_nonce);

	auto sum = sha256(msg);
	uint64_t v = 0;
	for (int i = 0; i < 8; ++i)
		v = v << 8 | sum[i];

	std::string code = std::to_string(v % 100'000'000);
	return std::string(8 - code.size(), '0') + code;
}

std::string format_code(std::string_view code)
{
	if (code.size() != 8)
		return std::string{code};
	return std::string{code.substr(0, 4)} + " " + std::string{code.substr(4)};
}

std::string key_fingerprint(const std::array<uint8_t, 32> & key)
{
	const std::string hex = to_hex(std::span<const uint8_t>{key.data(), 16});
	std::string out;
	for (size_t i = 0; i < hex.size(); i += 4)
	{
		if (i)
			out += ' ';
		out += hex.substr(i, 4);
	}
	return out;
}

pairing_outcome finish_pairing(server & srv)
{
	if (srv.server_key_sha256.empty())
		return pairing_outcome::check_key;
	srv.paired = true;
	return pairing_outcome::paired;
}

void accept_key(server & srv, const std::array<uint8_t, 32> & key)
{
	srv.server_key_sha256 = to_hex(key);
	srv.paired = true;
}

std::string pairing_url_to_show(const server & srv, std::string_view url)
{
	if (srv.server_key_sha256.empty())
		return {};
	return std::string{url};
}

// Store

store store::load(const std::filesystem::path & path)
{
	store s;
	std::error_code ec;
	if (not std::filesystem::exists(path, ec))
		return s;

	try
	{
		simdjson::dom::parser parser;
		simdjson::dom::element root = parser.load(path.native());
		simdjson::dom::array servers = root["servers"];
		for (simdjson::dom::element entry: servers)
		{
			try
			{
				simdjson::dom::object o = entry;
				int64_t port = o["port"].get_int64();
				if (port < 1 or port > 65535)
					throw std::out_of_range("port out of range");
				server srv{
				        .id = (std::string)o["id"],
				        .name = (std::string)o["name"],
				        .host = (std::string)o["host"],
				        .port = (int)port,
				        .tls_key = (std::string)o["tls_key"],
				        .tls_cert = (std::string)o["tls_cert"],
				        .server_key_sha256 = get_string(o, "server_key_sha256"),
				        .paired = o["paired"].get_bool(),
				};
				if (srv.id.empty() or srv.host.empty() or srv.tls_key.empty() or srv.tls_cert.empty())
					throw std::runtime_error("incomplete entry");
				if (not srv.server_key_sha256.empty())
					parse_hex32(srv.server_key_sha256);
				else if (srv.paired)
					throw std::runtime_error("paired without a pinned key");
				s.servers.push_back(std::move(srv));
			}
			catch (std::exception &)
			{
				// Keep it for save(), so an entry a newer version wrote is not lost
				s.unparsed.push_back(simdjson::minify(entry));
			}
		}
	}
	catch (simdjson::simdjson_error & e)
	{
		// Unreadable is not damaged: leave the file alone, save() would replace it, so refuse
		if (e.error() == simdjson::IO_ERROR)
			throw;

		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
		                       std::chrono::system_clock::now().time_since_epoch())
		                       .count();
		auto backup = path;
		backup += ".bad-" + std::to_string(seconds);
		for (int n = 1; std::filesystem::exists(backup, ec); ++n)
		{
			backup = path;
			backup += ".bad-" + std::to_string(seconds) + "-" + std::to_string(n);
		}
		std::filesystem::rename(path, backup, ec);
		if (ec)
			throw std::runtime_error("cannot move the damaged " + path.string() + " aside: " + ec.message());
		s = {};
	}
	return s;
}

void store::save(const std::filesystem::path & path) const
{
	std::ostringstream json;
	json << "{\"servers\":[";
	bool first = true;
	for (const auto & srv: servers)
	{
		if (not first)
			json << ",";
		first = false;
		json << "{\"id\":" << json_string(srv.id)
		     << ",\"name\":" << json_string(srv.name)
		     << ",\"host\":" << json_string(srv.host)
		     << ",\"port\":" << srv.port
		     << ",\"tls_key\":" << json_string(srv.tls_key)
		     << ",\"tls_cert\":" << json_string(srv.tls_cert)
		     << ",\"server_key_sha256\":" << json_string(srv.server_key_sha256)
		     << ",\"paired\":" << (srv.paired ? "true" : "false") << "}";
	}
	for (const auto & entry: unparsed)
	{
		if (not first)
			json << ",";
		first = false;
		json << entry;
	}
	json << "]}";
	wivrn::write_private_file(path, json.str());
}

server * store::find(std::string_view id)
{
	for (auto & srv: servers)
		if (srv.id == id)
			return &srv;
	return nullptr;
}

// Replies

std::string parse_error(std::string_view json)
{
	try
	{
		simdjson::dom::parser parser;
		simdjson::dom::object o = parser.parse(simdjson::padded_string{json});
		return get_string(o, "error");
	}
	catch (std::exception &)
	{
		return {};
	}
}

std::vector<app> parse_apps(std::string_view json)
{
	simdjson::dom::parser parser;
	simdjson::dom::object root = parser.parse(simdjson::padded_string{json});
	std::vector<app> apps;
	for (simdjson::dom::object o: root["apps"].get_array())
	{
		app a{
		        .id = (std::string)o["id"],
		        .title = get_string(o, "title"),
		        .cover = get_string(o, "cover"),
		};
		if (a.title.empty())
			a.title = a.id;
		apps.push_back(std::move(a));
	}
	return apps;
}

session parse_session(std::string_view json)
{
	simdjson::dom::parser parser;
	simdjson::dom::object o = parser.parse(simdjson::padded_string{json});
	session s{
	        .state = (std::string)o["state"],
	        .app = get_string(o, "app"),
	        .title = get_string(o, "title"),
	        .host = get_string(o, "host"),
	        .server_key = get_string(o, "serverKey"),
	        .message = get_string(o, "message"),
	};
	int64_t port;
	if (o["port"].get(port) == simdjson::SUCCESS)
	{
		if (port < 0 or port > 65535)
			throw std::out_of_range("port out of range");
		s.port = port;
	}
	bool connected;
	if (o["headsetConnected"].get(connected) == simdjson::SUCCESS)
		s.headset_connected = connected;

	if (s.state == "ready")
	{
		// The key is pinned for the stream: never connect without one
		auto key = from_hex(s.server_key);
		if (s.host.empty() or s.port == 0 or not key or key->size() != 56)
			throw std::runtime_error("the session is ready without an address and a 56-byte server key");
	}
	return s;
}

// HTTP

client::response client::request(const char * method, std::string_view path, std::string_view json_body, const std::optional<std::array<uint8_t, 32>> & pin, long timeout_s, size_t max_body)
{
	struct state
	{
		std::string body;
		size_t max_body;
		bool too_big = false;
		const std::atomic<bool> * cancelled;
		std::string retry_after;
	} st{.max_body = max_body, .cancelled = cancelled};

	std::unique_ptr<CURL, deleter<CURL, curl_easy_cleanup>> curl{curl_easy_init()};
	if (not curl)
		throw api_error(0, "curl_easy_init failed");
	CURL * c = curl.get();

	// IPv6 literals go in brackets
	std::string host = srv.host.find(':') != std::string::npos ? "[" + srv.host + "]" : srv.host;
	std::string url = "https://" + host + ":" + std::to_string(srv.port) + std::string{path};

	curl_blob cert{.data = const_cast<char *>(srv.tls_cert.data()), .len = srv.tls_cert.size(), .flags = CURL_BLOB_NOCOPY};
	curl_blob key{.data = const_cast<char *>(srv.tls_key.data()), .len = srv.tls_key.size(), .flags = CURL_BLOB_NOCOPY};

	std::string pin_option;
	if (pin)
		pin_option = "sha256//" + base64(*pin);

	auto check = [](CURLcode rc, const char * what) {
		if (rc != CURLE_OK)
			throw api_error(0, std::string{"libcurl: "} + what + ": " + curl_easy_strerror(rc));
	};

	curl_slist * headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "Accept: application/json");
	std::unique_ptr<curl_slist, deleter<curl_slist, curl_slist_free_all>> headers_ptr{headers};

	check(curl_easy_setopt(c, CURLOPT_URL, url.c_str()), "URL");
	check(curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https"), "protocols");
	check(curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L), "redirects");
	check(curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L), "signals");
	check(curl_easy_setopt(c, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_3), "TLS version");
	// The front door's certificate is its own, not a CA's: it is trusted by its pinned key
	check(curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L), "verify peer");
	check(curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L), "verify host");
	// A resumed session skips the certificate exchange the pin and certinfo read
	check(curl_easy_setopt(c, CURLOPT_SSL_SESSIONID_CACHE, 0L), "session cache");
	check(curl_easy_setopt(c, CURLOPT_SSLCERTTYPE, "PEM"), "cert type");
	check(curl_easy_setopt(c, CURLOPT_SSLCERT_BLOB, &cert), "client certificate");
	check(curl_easy_setopt(c, CURLOPT_SSLKEYTYPE, "PEM"), "key type");
	check(curl_easy_setopt(c, CURLOPT_SSLKEY_BLOB, &key), "client key");
	if (pin)
		check(curl_easy_setopt(c, CURLOPT_PINNEDPUBLICKEY, pin_option.c_str()), "pinned key"); // fail closed without support
	else
		check(curl_easy_setopt(c, CURLOPT_CERTINFO, 1L), "certificate info");
	check(curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L), "connect timeout");
	check(curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_s), "timeout");
	check(curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers), "headers");
	check(curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method), "method");
	if (std::string_view{method} == "POST")
	{
		// Never a null body: libcurl would read one from stdin
		static const char empty[] = "";
		check(curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)json_body.size()), "body size");
		check(curl_easy_setopt(c, CURLOPT_POSTFIELDS, json_body.empty() ? empty : json_body.data()), "body");
	}
	else
		check(curl_easy_setopt(c, CURLOPT_HTTPGET, 1L), "GET");

	size_t (*write_cb)(char *, size_t, size_t, void *) = [](char * data, size_t size, size_t n, void * user) -> size_t {
		auto & st = *static_cast<state *>(user);
		if (st.body.size() + size * n > st.max_body)
		{
			st.too_big = true;
			return CURL_WRITEFUNC_ERROR;
		}
		st.body.append(data, size * n);
		return size * n;
	};
	check(curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb), "write callback");
	check(curl_easy_setopt(c, CURLOPT_WRITEDATA, &st), "write data");

	size_t (*header_cb)(char *, size_t, size_t, void *) = [](char * data, size_t size, size_t n, void * user) -> size_t {
		auto & st = *static_cast<state *>(user);
		std::string_view line{data, size * n};
		constexpr std::string_view name = "retry-after:";
		if (line.size() > name.size())
		{
			std::string lower{line.substr(0, name.size())};
			for (char & ch: lower)
				ch = std::tolower((unsigned char)ch);
			if (lower == name)
			{
				auto v = line.substr(name.size());
				while (not v.empty() and (v.front() == ' ' or v.front() == '\t'))
					v.remove_prefix(1);
				while (not v.empty() and (v.back() == '\r' or v.back() == '\n' or v.back() == ' '))
					v.remove_suffix(1);
				st.retry_after = v;
			}
		}
		return size * n;
	};
	check(curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb), "header callback");
	check(curl_easy_setopt(c, CURLOPT_HEADERDATA, &st), "header data");

	int (*progress_cb)(void *, curl_off_t, curl_off_t, curl_off_t, curl_off_t) = [](void * user, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
		auto & st = *static_cast<state *>(user);
		return st.cancelled and *st.cancelled ? 1 : 0;
	};
	check(curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, progress_cb), "progress callback");
	check(curl_easy_setopt(c, CURLOPT_XFERINFODATA, &st), "progress data");
	check(curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L), "progress");

	CURLcode rc = curl_easy_perform(c);
	if (rc == CURLE_ABORTED_BY_CALLBACK)
		throw api_error(0, "cancelled");
	if (st.too_big)
		throw api_error(0, "the reply is too large");
	if (rc == CURLE_SSL_PINNEDPUBKEYNOTMATCH)
		throw api_error(0, "the server presented a different key than the one this headset paired with");
	if (rc != CURLE_OK)
		throw api_error(0, curl_easy_strerror(rc));

	response r;
	r.body = std::move(st.body);
	r.retry_after = std::move(st.retry_after);
	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);

	if (not pin)
	{
		// The leaf certificate, as the TLS backend reported it
		curl_certinfo * info = nullptr;
		if (curl_easy_getinfo(c, CURLINFO_CERTINFO, &info) != CURLE_OK or not info or info->num_of_certs < 1)
			throw api_error(0, "cannot read the server's certificate");
		for (curl_slist * s = info->certinfo[0]; s; s = s->next)
		{
			std::string_view field{s->data};
			if (field.starts_with("Cert:"))
				r.server_key = certificate_key_sha256(field.substr(5));
		}
		if (not r.server_key)
			throw api_error(0, "cannot read the server's certificate");
	}

	return r;
}

namespace
{
constexpr size_t json_max = 256 * 1024;
constexpr size_t cover_max = 8 * 1024 * 1024;

[[noreturn]] void fail(const client::response & r)
{
	std::string msg = parse_error(r.body);
	if (msg.empty())
		msg = "HTTP " + std::to_string(r.status);
	throw api_error((int)r.status, msg);
}

std::optional<std::array<uint8_t, 32>> pinned(const server & srv)
{
	if (srv.server_key_sha256.empty())
		return std::nullopt;
	return parse_hex32(srv.server_key_sha256);
}

std::optional<std::array<uint8_t, 32>> required_pin(const server & srv)
{
	auto pin = pinned(srv);
	if (not pin)
		throw api_error(0, "this headset is not paired with this server");
	return pin;
}
} // namespace

pair_reply client::pair(std::string_view wivrn_key, std::string_view name, const std::array<uint8_t, 32> & commitment)
{
	std::string body = "{\"publicKey\":" + json_string(wivrn_key) +
	                   ",\"name\":" + json_string(name) +
	                   ",\"commitment\":" + json_string(to_hex(commitment)) + "}";

	// Re-pairing keeps the key this headset already trusts
	auto pin = pinned(srv);
	auto r = request("POST", "/vr/v1/pair", body, pin, 30, json_max);
	if (r.status == 429)
	{
		int wait = 5;
		try
		{
			wait = std::clamp(std::stoi(r.retry_after), 1, 60);
		}
		catch (std::exception &)
		{}
		throw api_error(429, std::to_string(wait));
	}
	if (r.status != 200)
		fail(r);

	simdjson::dom::parser parser;
	simdjson::dom::object o = parser.parse(simdjson::padded_string{r.body});
	pair_reply reply{
	        .pairing_id = (std::string)o["pairingID"],
	        .server_nonce = parse_hex32((std::string_view)o["serverNonce"]),
	        .pairing_url = get_string(o, "pairingURL"),
	        .server_key = pin ? *pin : *r.server_key,
	};
	return reply;
}

void client::confirm(const std::array<uint8_t, 32> & server_key, std::string_view pairing_id, const std::array<uint8_t, 32> & nonce)
{
	std::string body = "{\"pairingID\":" + json_string(pairing_id) + ",\"nonce\":" + json_string(to_hex(nonce)) + "}";
	// The front door holds this for 3 minutes, plus up to 30s to record the Headset
	auto r = request("POST", "/vr/v1/pair/confirm", body, server_key, 240, json_max);
	if (r.status != 200)
		fail(r);
}

std::vector<app> client::apps()
{
	auto r = request("GET", "/vr/v1/apps", {}, required_pin(srv), 30, json_max);
	if (r.status != 200)
		fail(r);
	return parse_apps(r.body);
}

std::vector<std::byte> client::cover(std::string_view path)
{
	// Only the front door's own paths: the reply is fetched with this headset's certificate
	if (not path.starts_with("/vr/v1/apps/"))
		throw api_error(0, "unexpected cover path");
	auto r = request("GET", path, {}, required_pin(srv), 30, cover_max);
	if (r.status != 200)
		fail(r);
	auto * b = reinterpret_cast<const std::byte *>(r.body.data());
	return {b, b + r.body.size()};
}

session client::launch(std::string_view app_id)
{
	auto r = request("POST", "/vr/v1/launch", "{\"app\":" + json_string(app_id) + "}", required_pin(srv), 60, json_max);
	if (r.status != 200 and r.status != 202)
		fail(r);
	return parse_session(r.body);
}

session client::get_session()
{
	auto r = request("GET", "/vr/v1/session", {}, required_pin(srv), 30, json_max);
	if (r.status != 200)
		fail(r);
	return parse_session(r.body);
}

void client::stop()
{
	auto r = request("POST", "/vr/v1/stop", {}, required_pin(srv), 30, json_max);
	if (r.status != 204 and r.status != 200)
		fail(r);
}
} // namespace fenrir
