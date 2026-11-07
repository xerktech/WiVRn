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

// Tests the XDG base directory rules: unset, empty or relative variables are ignored, the same
// rule Monado's runtime dir follows (patches/monado/0014).

#include "utils/xdg_base_directory.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <vector>

#define CHECK(x)                                                                            \
	do                                                                                  \
	{                                                                                   \
		if (not(x))                                                                 \
		{                                                                           \
			std::cerr << __FILE__ << ":" << __LINE__ << ": FAILED " #x << "\n"; \
			std::exit(1);                                                       \
		}                                                                           \
	} while (0)

namespace
{
using paths = std::vector<std::filesystem::path>;

void set(const char * name, const char * value)
{
	if (value)
		::setenv(name, value, 1);
	else
		::unsetenv(name);
}
} // namespace

int main()
{
	set("HOME", "/home/u");

	for (const char * ignored: {(const char *)nullptr, "", "relative", "./x", "~/x"})
	{
		set("XDG_CONFIG_HOME", ignored);
		set("XDG_CACHE_HOME", ignored);
		set("XDG_DATA_HOME", ignored);
		set("XDG_RUNTIME_DIR", ignored);
		set("XDG_CONFIG_DIRS", ignored);
		set("XDG_DATA_DIRS", ignored);
		CHECK(xdg_config_home() == "/home/u/.config");
		CHECK(xdg_cache_home() == "/home/u/.cache");
		CHECK(xdg_data_home() == "/home/u/.local/share");
		CHECK(xdg_runtime_dir() == "/tmp");
		CHECK(xdg_config_dirs() == paths{"/etc/xdg"});
		CHECK(xdg_data_dirs(false) == (paths{"/usr/local/share", "/usr/share"}));
	}

	set("XDG_CONFIG_HOME", "/c");
	set("XDG_CACHE_HOME", "/k");
	set("XDG_DATA_HOME", "/d");
	set("XDG_RUNTIME_DIR", "/run/user/1");
	CHECK(xdg_config_home() == "/c");
	CHECK(xdg_cache_home() == "/k");
	CHECK(xdg_data_home() == "/d");
	CHECK(xdg_runtime_dir() == "/run/user/1");

	// Relative and empty list entries are dropped, absolute ones kept in order
	set("XDG_CONFIG_DIRS", "rel::/a:/b");
	set("XDG_DATA_DIRS", "/s1:x:/s2:");
	CHECK(xdg_config_dirs() == (paths{"/a", "/b"}));
	CHECK(xdg_data_dirs(true) == (paths{"/d", "/s1", "/s2"}));

	// Without a usable HOME the old "." fallback stays, never a path built from garbage
	set("XDG_CONFIG_HOME", nullptr);
	for (const char * home: {(const char *)nullptr, "", "relative"})
	{
		set("HOME", home);
		CHECK(xdg_config_home() == ".");
	}

	std::cout << "All XDG base directory tests passed\n";
	return 0;
}
