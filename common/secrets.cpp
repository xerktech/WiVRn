/*
 * WiVRn VR streaming
 * Copyright (C) 2022  Guillaume Meunier <guillaume.meunier@centraliens.net>
 * Copyright (C) 2022  Patrick Nicolas <patricknicolas@laposte.net>
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

#include "secrets.h"
#include <cstring>
#include <type_traits>

secrets::secrets(std::vector<uint8_t> dh, const std::string & pin)
{
	// The key material is the DH output; the PIN is mixed in as context. (Upstream used PBKDF2,
	// which ignores the DH secret it was given, so the keys only depended on the PIN.)
	std::vector<uint8_t> secret = crypto::hkdf_sha256(dh, "wivrn session keys", pin, sizeof(*this));

	static_assert(std::is_standard_layout_v<secrets>);
	static_assert(std::has_unique_object_representations_v<secrets>);
	memcpy(this, secret.data(), secret.size());
}

static std::vector<uint8_t> concat(std::vector<uint8_t> a, const std::vector<uint8_t> & b)
{
	a.insert(a.end(), b.begin(), b.end());
	return a;
}

secrets secrets::headset(crypto::key & headset_key, crypto::key & server_ephemeral, crypto::key & server_identity, const std::string & pin)
{
	return secrets{
	        concat(crypto::key::diffie_hellman(headset_key, server_ephemeral),
	               crypto::key::diffie_hellman(headset_key, server_identity)),
	        pin};
}

secrets secrets::server(crypto::key & server_ephemeral, crypto::key & server_identity, crypto::key & headset_key, const std::string & pin)
{
	return secrets{
	        concat(crypto::key::diffie_hellman(server_ephemeral, headset_key),
	               crypto::key::diffie_hellman(server_identity, headset_key)),
	        pin};
}

std::string pin_check_secret(const std::string & pin, const crypto::key & server_identity, const crypto::key & headset_key)
{
	auto digest = crypto::sha256(concat(server_identity.raw_public_key(), headset_key.raw_public_key()));

	std::string secret = pin + ":";
	for (uint8_t byte: digest)
	{
		secret += "0123456789abcdef"[byte >> 4];
		secret += "0123456789abcdef"[byte & 0xf];
	}

	return secret;
}
