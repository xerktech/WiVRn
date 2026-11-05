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

#include "identity.h"

#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>

namespace
{
std::string to_hex(const std::vector<uint8_t> & bytes)
{
	std::string hex;
	for (uint8_t byte: bytes)
	{
		hex += "0123456789abcdef"[byte >> 4];
		hex += "0123456789abcdef"[byte & 0xf];
	}
	return hex;
}

// Write content to a new temporary file next to path, readable by the owner only. A unique
// name means concurrent writers never share it and a stale file is never reused.
std::filesystem::path write_temporary_file(const std::filesystem::path & path, const std::string & content)
{
	std::filesystem::create_directories(path.parent_path());

	std::string tmp = path.string() + ".XXXXXX";
	int fd = ::mkstemp(tmp.data()); // created with mode 0600
	if (fd < 0)
		throw std::system_error(errno, std::system_category(), "Cannot write " + tmp);

	size_t written = 0;
	int err = 0;
	while (written < content.size())
	{
		ssize_t n = ::write(fd, content.data() + written, content.size() - written);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			err = errno;
			break;
		}
		written += n;
	}

	if (err == 0 and ::fsync(fd) < 0)
		err = errno;
	if (::close(fd) < 0 and err == 0)
		err = errno;

	if (err != 0)
	{
		std::filesystem::remove(tmp);
		throw std::system_error(err, std::system_category(), "Cannot write " + tmp);
	}

	return tmp;
}

// Atomically replace path
void write_private_file(const std::filesystem::path & path, const std::string & content)
{
	auto tmp = write_temporary_file(path, content);
	std::error_code ec;
	std::filesystem::rename(tmp, path, ec);
	if (ec)
	{
		std::filesystem::remove(tmp);
		throw std::system_error(ec, "Cannot write " + path.string());
	}
}

// Atomically create path, unless it already exists. Returns false if another writer created it first.
bool create_private_file(const std::filesystem::path & path, const std::string & content)
{
	auto tmp = write_temporary_file(path, content);

	// link() fails with EEXIST instead of overwriting, so the first writer wins
	int r = ::link(tmp.c_str(), path.c_str());
	int err = errno;
	std::filesystem::remove(tmp);

	if (r == 0)
		return true;
	if (err == EEXIST)
		return false;
	throw std::system_error(err, std::system_category(), "Cannot write " + path.string());
}

std::string read_file(const std::filesystem::path & path)
{
	std::ifstream f{path};
	return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
} // namespace

namespace
{
crypto::key load_identity_key(const std::filesystem::path & path)
{
	crypto::key key;
	try
	{
		key = crypto::key::from_private_key(read_file(path));
	}
	catch (std::exception & e)
	{
		throw std::runtime_error("Cannot read identity key " + path.string() + ": " + e.what());
	}
	if (EVP_PKEY_get_base_id(key) != EVP_PKEY_X448)
		throw std::runtime_error(path.string() + " is not an X448 private key");
	return key;
}
} // namespace

crypto::key wivrn::load_or_create_identity_key(const std::filesystem::path & path)
{
	if (std::filesystem::exists(path))
		return load_identity_key(path);

	crypto::key key = crypto::key::generate_x448_keypair();
	if (create_private_file(path, key.private_key()))
		return key;

	// Lost a race with another connection: use the key it stored. If the path still does not
	// resolve to a file, it is something like a dangling symlink, never replace it.
	if (not std::filesystem::exists(path))
		throw std::runtime_error("Cannot create identity key " + path.string() + ": the path exists but is not a readable file");

	return load_identity_key(path);
}

bool wivrn::is_trusted_key(const std::filesystem::path & path, const crypto::key & key)
{
	const std::string wanted = to_hex(key.raw_public_key());

	std::ifstream f{path};
	for (std::string line; std::getline(f, line);)
	{
		if (line == wanted)
			return true;
	}
	return false;
}

void wivrn::add_trusted_key(const std::filesystem::path & path, const crypto::key & key)
{
	if (is_trusted_key(path, key))
		return;

	std::string content = std::filesystem::exists(path) ? read_file(path) : std::string{};
	if (not content.empty() and content.back() != '\n')
		content += '\n';
	content += to_hex(key.raw_public_key()) + '\n';

	write_private_file(path, content);
}
