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

#pragma once

#include "crypto.h"
#include <filesystem>
#include <string>

namespace wivrn
{
// Load the X448 private key stored at path, or generate one and store it (owner-only
// permissions) if the file does not exist. Throws if the file exists but is not a valid key, so a
// corrupted identity is never silently replaced.
crypto::key load_or_create_identity_key(const std::filesystem::path & path);

// Set of public keys trusted by their owner, one hex-encoded raw public key per line.
// The headset uses it to pin the identity key of each server it paired with.
bool is_trusted_key(const std::filesystem::path & path, const crypto::key & key);
void add_trusted_key(const std::filesystem::path & path, const crypto::key & key);

// Forget every trusted key: connecting to any server without its PIN is refused until it is paired
// again. A missing file is not an error.
void forget_trusted_keys(const std::filesystem::path & path, std::error_code & ec);

// Atomically replace path with content, readable by the owner only
void write_private_file(const std::filesystem::path & path, const std::string & content);
} // namespace wivrn
