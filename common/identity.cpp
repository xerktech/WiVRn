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

// Write content to path atomically, readable by the owner only
void write_private_file(const std::filesystem::path & path, const std::string & content)
{
	std::filesystem::create_directories(path.parent_path());

	std::filesystem::path tmp = path;
	tmp += ".new";

	int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		throw std::system_error(errno, std::system_category(), "Cannot write " + tmp.string());

	size_t written = 0;
	while (written < content.size())
	{
		ssize_t n = ::write(fd, content.data() + written, content.size() - written);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			int err = errno;
			::close(fd);
			throw std::system_error(err, std::system_category(), "Cannot write " + tmp.string());
		}
		written += n;
	}

	if (::fsync(fd) < 0 or ::close(fd) < 0)
		throw std::system_error(errno, std::system_category(), "Cannot write " + tmp.string());

	std::filesystem::rename(tmp, path);
}

std::string read_file(const std::filesystem::path & path)
{
	std::ifstream f{path};
	return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
} // namespace

crypto::key wivrn::load_or_create_identity_key(const std::filesystem::path & path)
{
	if (std::filesystem::exists(path))
	{
		crypto::key key = crypto::key::from_private_key(read_file(path));
		if (EVP_PKEY_get_base_id(key) != EVP_PKEY_X448)
			throw std::runtime_error(path.string() + " is not an X448 private key");
		return key;
	}

	crypto::key key = crypto::key::generate_x448_keypair();
	write_private_file(path, key.private_key());
	return key;
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
