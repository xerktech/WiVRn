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

// Client of fenrir's VR front door (fenrir docs/vr-native-session.md, XERK-2808): pair the
// headset once by a code its user types on fenrir's pairing page, then list, launch and stop VR
// Apps over mutual TLS. Kept free of the GUI, i18n and logging so it can be tested on its own.

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fenrir
{
// A front door this headset knows, stored in fenrir.json, apart from client.json so a damaged
// client.json never loses a pairing (and the other way round).
struct server
{
	std::string id; // random, stable: names the entry in the GUI
	std::string name;
	std::string host;
	int port = 0;

	// This headset's TLS identity for this server, PEM. The key never leaves the headset: only
	// the certificate is sent, in the TLS handshake.
	std::string tls_key;
	std::string tls_cert;

	// SHA-256 of the front door's certificate SubjectPublicKeyInfo, hex. Learnt from the pairing
	// exchange that the code authenticates, and enforced on every later connection.
	std::string server_key_sha256;
	bool paired = false;
};

struct store
{
	std::vector<server> servers;
	// Entries that could not be parsed, as minified JSON, written back by save()
	std::vector<std::string> unparsed;

	// A missing file is an empty store. A file that cannot be parsed is moved aside to
	// <path>.bad-<unix seconds>, never overwritten by the next save().
	static store load(const std::filesystem::path & path);
	// Atomic, owner-only (the file holds the TLS private keys)
	void save(const std::filesystem::path & path) const;

	server * find(std::string_view id);
};

// The headset's TLS identity: a P-256 key and a self-signed certificate over it, PEM
struct tls_identity
{
	std::string key;
	std::string cert;
};
tls_identity make_tls_identity();

std::string random_id();
std::array<uint8_t, 32> random_nonce();
std::array<uint8_t, 32> sha256(std::string_view data);
std::string to_hex(std::span<const uint8_t> bytes);
// Exactly 2n hex digits for n bytes, either case
std::optional<std::vector<uint8_t>> from_hex(std::string_view hex);

// SHA-256 of a PEM certificate's DER SubjectPublicKeyInfo: how fenrir names a TLS key
std::array<uint8_t, 32> certificate_key_sha256(std::string_view pem);

// WiVRn's public key in Headset form: the PEM's base64 body, without armour or newlines
std::string wivrn_key_body(std::string_view pem);

// The 8-digit code both sides show (fenrir pkg/moonlight/vrdoor.go vrPairingCode): the first 8
// bytes of SHA-256 over "direwolf-vr-pair-v1", NUL, the server's and the client's TLS key
// hashes, SHA-256 of the WiVRn key text, the server nonce and the headset nonce, big-endian,
// mod 10^8, with leading zeros. Keep the two in step.
std::string pairing_code(
        const std::array<uint8_t, 32> & server_key,
        const std::array<uint8_t, 32> & client_key,
        std::string_view wivrn_key,
        const std::array<uint8_t, 32> & server_nonce,
        const std::array<uint8_t, 32> & headset_nonce);

// "12345678" -> "1234 5678", for reading out
std::string format_code(std::string_view code);

// An HTTP error from the front door: its status and its {"error"} text. status is 0 when no reply
// arrived (network, TLS, or a pinned-key mismatch).
struct api_error : std::runtime_error
{
	int status;
	explicit api_error(int status, const std::string & message) :
	        std::runtime_error(message), status(status) {}
};

struct app
{
	std::string id;
	std::string title;
	std::string cover; // a path on the front door, or empty
};

struct session
{
	std::string state; // none, starting, ready, stopping, other
	std::string app;
	std::string title;
	std::string host;
	int port = 0;
	std::string server_key; // the session's WiVRn identity key, raw X448, hex
	bool headset_connected = false;
	std::string message;
};

struct pair_reply
{
	std::string pairing_id;
	std::array<uint8_t, 32> server_nonce;
	std::string pairing_url;
	// The front door's key hash this reply came with
	std::array<uint8_t, 32> server_key;
};

// One front door, with this headset's identity. Calls block: run them off the render thread.
// cancelled, if set, aborts a call in flight.
class client
{
	const server & srv;
	const std::atomic<bool> * cancelled;

public:
	client(const server & srv, const std::atomic<bool> * cancelled = nullptr) :
	        srv(srv), cancelled(cancelled) {}

	// POST /vr/v1/pair. When srv has no pinned key yet, the reply carries the key the front door
	// presented, which the caller pins for confirm() and, once paired, for good.
	pair_reply pair(std::string_view wivrn_key, std::string_view name, const std::array<uint8_t, 32> & commitment);

	// POST /vr/v1/pair/confirm, pinned to server_key: held until the code is entered (true), or
	// until the front door gives up (api_error 408).
	void confirm(const std::array<uint8_t, 32> & server_key, std::string_view pairing_id, const std::array<uint8_t, 32> & nonce);

	std::vector<app> apps();
	std::vector<std::byte> cover(std::string_view path);
	session launch(std::string_view app_id);
	session get_session();
	void stop();

	struct response
	{
		long status = 0;
		std::string body;
		std::string retry_after;
		std::optional<std::array<uint8_t, 32>> server_key; // only when not pinned
	};

	// pin: the key the front door must present; without it any key is accepted and reported.
	response request(const char * method, std::string_view path, std::string_view json_body, const std::optional<std::array<uint8_t, 32>> & pin, long timeout_s, size_t max_body);
};

// Parsers for the front door's replies, exposed for tests. They throw on malformed input.
std::vector<app> parse_apps(std::string_view json);
session parse_session(std::string_view json);
std::string parse_error(std::string_view json); // {"error"}, or empty
} // namespace fenrir
