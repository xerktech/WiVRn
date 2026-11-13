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

// Network bytes that are not a valid bool or enum value must be rejected with
// deserialization_error, while every valid value still round-trips.

#include "wivrn_packets.h"
#include "wivrn_serialization.h"

#include <cstdlib>
#include <iostream>
#include <memory>

using namespace wivrn;

namespace
{
// std::byte has its own traits but must hash like any enum with no enumerators did before,
// or the protocol hash would change
enum class no_enumerators : uint8_t
{
};
static_assert(serialization_type_hash<std::byte>(0) == serialization_type_hash<no_enumerators>(0));

int failures = 0;

void check(bool ok, const char * what)
{
	if (not ok)
	{
		std::cerr << "FAIL: " << what << std::endl;
		++failures;
	}
}

std::vector<uint8_t> to_bytes(serialization_packet & p)
{
	std::vector<uint8_t> out;
	for (auto span: static_cast<std::vector<std::span<uint8_t>> &>(p))
		out.insert(out.end(), span.begin(), span.end());
	return out;
}

template <typename T>
std::vector<uint8_t> serialize(const T & value)
{
	serialization_packet p;
	p.serialize(value);
	return to_bytes(p);
}

template <typename T>
T deserialize(const std::vector<uint8_t> & bytes)
{
	std::shared_ptr<uint8_t[]> memory(new uint8_t[bytes.size()]);
	std::ranges::copy(bytes, memory.get());
	deserialization_packet p(memory, std::span(memory.get(), bytes.size()));
	return p.deserialize<T>();
}

template <typename T>
bool rejects(const std::vector<uint8_t> & bytes)
{
	try
	{
		deserialize<T>(bytes);
		return false;
	}
	catch (deserialization_error &)
	{
		return true;
	}
}
} // namespace

int main()
{
	// bool: only 0 and 1 are valid
	check(deserialize<bool>({0}) == false, "bool 0 accepted");
	check(deserialize<bool>({1}) == true, "bool 1 accepted");
	for (uint8_t b: {2, 31, 255})
		check(rejects<bool>({b}), "bool > 1 rejected");

	// bool inside a struct, past the struct's trivial fast path
	{
		auto bytes = serialize(to_headset::feature_control{.f = to_headset::feature_control::microphone, .state = true});
		check(deserialize<to_headset::feature_control>(bytes).state, "feature_control round-trips");
		bytes.back() = 2;
		check(rejects<to_headset::feature_control>(bytes), "bool field > 1 rejected");
	}

	// enums: unknown values are rejected
	check(rejects<XrSessionState>(serialize<int32_t>(XR_SESSION_STATE_EXITING + 1)), "unknown XrSessionState rejected");
	check(rejects<stream_tab>({uint8_t(magic_enum::enum_count<stream_tab>())}), "unknown stream_tab rejected");

	// every device_id is accepted, gamepad ids (128+) included
	for (auto id: magic_enum::enum_values<device_id>())
		check(deserialize<device_id>(serialize(id)) == id, "device_id round-trips");
	check(magic_enum::enum_contains(device_id::GAMEPAD_THUMBSTICK_RIGHT_Y), "last device_id is reflected");
	check(rejects<device_id>({255}), "unknown device_id rejected");

	// std::byte carries arbitrary data
	{
		std::vector<std::byte> image;
		for (int i = 0; i < 256; ++i)
			image.push_back(std::byte(i));
		auto icon = deserialize<to_headset::application_icon>(serialize(to_headset::application_icon{.id = "x", .image = image}));
		check(icon.image == image, "std::byte vector round-trips");
	}

	if (failures)
		return EXIT_FAILURE;
	std::cout << "serialization tests passed" << std::endl;
	return EXIT_SUCCESS;
}
