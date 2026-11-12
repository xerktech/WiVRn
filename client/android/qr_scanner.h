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

#include <functional>
#include <memory>
#include <optional>
#include <string>

// Reads QR codes from a Quest 3/3S passthrough camera (Meta's Passthrough Camera API: Camera2,
// horizonos.permission.HEADSET_CAMERA, Horizon OS v74+) until one passes accept (XERK-2812).
// The camera only delivers images while passthrough is on.
class qr_scanner
{
	struct impl;
	std::unique_ptr<impl> p;

public:
	// The permission the caller must hold before constructing one
	static constexpr const char * permission = "horizonos.permission.HEADSET_CAMERA";

	// Runs on the camera's thread, for every QR code seen until one is accepted
	using accept_fn = std::function<bool(const std::string &)>;

	// Opens the camera; throws std::runtime_error when there is none or it can't be opened
	explicit qr_scanner(accept_fn accept);
	~qr_scanner();
	qr_scanner(const qr_scanner &) = delete;
	qr_scanner & operator=(const qr_scanner &) = delete;

	// The accepted text, once there is one: no frame is decoded after it
	std::optional<std::string> result() const;
	// A QR code was read but not accepted (someone else's code)
	bool saw_other() const;
	// Set when the camera failed or was taken away
	std::optional<std::string> error() const;
};
