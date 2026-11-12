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

// Reads the QR code fenrir's pairing page draws (XERK-2812) the way the headset's camera reader
// does: tests/data/fenrir_qr.pgm is fenrir's vrQRCode for its TestVRPairingLink vector, drawn
// on the page's dark background. Run from the repository root.

#include "../android/qr_decode.h"
#include "../fenrir.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

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

struct pgm
{
	int width = 0, height = 0;
	std::vector<uint8_t> pixels;
};

pgm read_pgm(const char * path)
{
	std::ifstream f(path, std::ios::binary);
	std::string magic;
	f >> magic;
	auto skip_comments = [&] {
		f >> std::ws;
		while (f.peek() == '#')
		{
			std::string line;
			std::getline(f, line);
			f >> std::ws;
		}
	};
	pgm img;
	int max = 0;
	skip_comments();
	f >> img.width;
	skip_comments();
	f >> img.height;
	skip_comments();
	f >> max;
	f.get();
	if (magic != "P5" or max != 255 or img.width <= 0 or img.height <= 0)
		return {};
	img.pixels.resize(size_t(img.width) * img.height);
	f.read(reinterpret_cast<char *>(img.pixels.data()), img.pixels.size());
	if (not f)
		return {};
	return img;
}

const std::string vector_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

bool reads_fenrir_link(const std::vector<std::string> & texts)
{
	if (texts.size() != 1)
		return false;
	auto link = fenrir::parse_pairing_link(texts[0]);
	return link and link->host == "fenrir.local" and link->port == 47990 and link->server_key_sha256 == vector_key;
}
} // namespace

int main()
{
	auto img = read_pgm("client/tests/data/fenrir_qr.pgm");
	CHECK(not img.pixels.empty());
	if (img.pixels.empty())
		return 1;

	CHECK(reads_fenrir_link(decode_qr(img.pixels.data(), img.width, img.height, img.width)));

	// A camera's Y plane has padded rows
	int stride = img.width + 64;
	std::vector<uint8_t> padded(size_t(stride) * img.height, 0xff);
	for (int y = 0; y < img.height; ++y)
		std::copy_n(&img.pixels[size_t(y) * img.width], img.width, &padded[size_t(y) * stride]);
	CHECK(reads_fenrir_link(decode_qr(padded.data(), img.width, img.height, stride)));

	// Upside down, as a camera may see it
	std::vector<uint8_t> flipped(img.pixels.rbegin(), img.pixels.rend());
	CHECK(reads_fenrir_link(decode_qr(flipped.data(), img.width, img.height, img.width)));

	// Nothing to read
	std::vector<uint8_t> blank(img.pixels.size(), 90);
	CHECK(decode_qr(blank.data(), img.width, img.height, img.width).empty());

	if (failures)
	{
		std::cerr << failures << " failure(s)\n";
		return 1;
	}
	std::cout << "qr_ut: all tests passed\n";
	return 0;
}
