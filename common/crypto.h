/*
 * WiVRn VR streaming
 * Copyright (C) 2024  Guillaume Meunier <guillaume.meunier@centraliens.net>
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

#pragma once

#include <array>
#include <cstdint>
#include <openssl/evp.h>
#include <span>
#include <string_view>
#include <vector>

namespace crypto
{
class key
{
	EVP_PKEY * pkey = nullptr;

public:
	key() = default;
	key(const key &) = delete;
	key & operator=(const key &) = delete;
	key(key && other) noexcept :
	        pkey(other.pkey)
	{
		other.pkey = nullptr;
	}

	key & operator=(key && other) noexcept
	{
		std::swap(pkey, other.pkey);

		return *this;
	}

	~key()
	{
		EVP_PKEY_free(pkey);
	}

	key(EVP_PKEY * pkey) :
	        pkey(pkey) {}

	static key from_public_key(std::string_view pem);
	static key from_private_key(std::string_view pem);
	static key generate_rsa_keypair(int bits);
	static key generate_x25519_keypair();
	static key generate_x448_keypair();

	std::string public_key() const;
	std::string private_key() const;

	// Raw public key bytes, works with x25519, x448 keys
	std::vector<uint8_t> raw_public_key() const;

	// Short fingerprint of the public key for people to compare by eye: the first 8 bytes of
	// SHA-256 over its DER SubjectPublicKeyInfo (the body of public_key()'s PEM), as hex in
	// groups of 4, e.g. "1a2b 3c4d 5e6f 7a8b". fenrir's headset confirmation page shows the same
	// value (pkg/controllers/library_headsets.go headsetFingerprint): keep the two in step.
	std::string public_key_fingerprint() const;

	operator EVP_PKEY *()
	{
		return pkey;
	}

	operator bool() const
	{
		return pkey != nullptr;
	}

	// Works with x25519, x448 keys
	static std::vector<uint8_t> diffie_hellman(key & my_key, key & peer_key);

	struct wrapped_secret
	{
		std::vector<uint8_t> wrapped;
		std::vector<uint8_t> secret;
	};

	// Works with RSA keys
	wrapped_secret encapsulate();
	std::vector<uint8_t> decapsulate(std::span<uint8_t> wrapped);
};

class cipher_context
{
protected:
	EVP_CIPHER_CTX * ctx = nullptr;

	cipher_context() = default;
	cipher_context(const cipher_context &) = delete;
	cipher_context & operator=(const cipher_context &) = delete;
	cipher_context(cipher_context && other) noexcept :
	        ctx(other.ctx),
	        key_length_(other.key_length_),
	        iv_length_(other.iv_length_),
	        block_size_(other.block_size_)
	{
		other.ctx = nullptr;
	}

	cipher_context & operator=(cipher_context && other) noexcept
	{
		std::swap(ctx, other.ctx);
		key_length_ = other.key_length_;
		iv_length_ = other.iv_length_;
		block_size_ = other.block_size_;
		return *this;
	}

	~cipher_context()
	{
		EVP_CIPHER_CTX_free(ctx);
	}
	size_t key_length_;
	size_t iv_length_;
	size_t block_size_;

public:
	void set_key(std::span<uint8_t> key);
	void set_iv(std::span<uint8_t> iv);
	void set_key_and_iv(std::span<uint8_t> key, std::span<uint8_t> iv);

	// AEAD ciphers only (e.g. AES-GCM): change the IV length, must be called before setting the IV
	void set_iv_length(size_t length);
	// AEAD ciphers only: authenticate additional data, after setting the IV and before any (en|de)crypt call
	void add_aad(std::span<const uint8_t> aad);

	static constexpr size_t tag_length = 16;

	size_t key_length() const
	{
		return key_length_;
	}

	size_t iv_length() const
	{
		return iv_length_;
	}

	size_t block_size() const
	{
		return block_size_;
	}

	operator bool() const
	{
		return ctx != nullptr;
	}
};

class encrypt_context : public cipher_context
{
public:
	encrypt_context() = default;
	encrypt_context(const encrypt_context &) = delete;
	encrypt_context & operator=(const encrypt_context &) = delete;
	encrypt_context(encrypt_context &&) noexcept = default;
	encrypt_context & operator=(encrypt_context &&) noexcept = default;
	~encrypt_context() = default;

	explicit encrypt_context(const EVP_CIPHER * cipher);

	std::vector<uint8_t> encrypt(std::span<uint8_t> plaintext);
	void encrypt_in_place(std::span<uint8_t> plaintext);
	void encrypt_in_place(std::span<std::span<uint8_t>> plaintext);

	// AEAD ciphers only: finish the message and write its authentication tag
	void finalize(std::span<uint8_t, tag_length> tag);
};

class decrypt_context : public cipher_context
{
public:
	decrypt_context() = default;
	decrypt_context(const decrypt_context &) = delete;
	decrypt_context & operator=(const decrypt_context &) = delete;
	decrypt_context(decrypt_context && other) noexcept = default;
	decrypt_context & operator=(decrypt_context &&) noexcept = default;
	~decrypt_context() = default;

	explicit decrypt_context(const EVP_CIPHER * cipher);

	std::vector<uint8_t> decrypt(std::span<uint8_t> ciphertext);
	void decrypt_in_place(std::span<uint8_t> ciphertext);
	void decrypt_in_place(std::span<std::span<uint8_t>> ciphertext);

	// AEAD ciphers only: finish the message and check its authentication tag.
	// Returns false if the message was tampered with: the decrypted data must then be discarded.
	[[nodiscard]] bool finalize(std::span<const uint8_t, tag_length> tag);
};

// Salt must be at least 8 characters
std::array<uint8_t, 32> sha256(std::span<const uint8_t> data);

// HKDF-SHA256 (RFC 5869): derives size bytes from the input key material
std::vector<uint8_t> hkdf_sha256(std::span<const uint8_t> key, std::string salt, std::string info, size_t size);

} // namespace crypto
