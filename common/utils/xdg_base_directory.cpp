/*
 * WiVRn VR streaming
 * Copyright (C) 2024  Guillaume Meunier <guillaume.meunier@centraliens.net>
 * Copyright (C) 2024  Patrick Nicolas <patricknicolas@laposte.net>
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

#include "strings.h"
#include <cstdlib>
#include <filesystem>

namespace
{
// Per the XDG base directory spec, a variable that is unset, empty or holds a relative path is
// ignored. Monado's u_file_get_runtime_dir applies the same rule (patches/monado/0014), so the
// IPC socket and WiVRn's own files agree on where things live.
const char * absolute_env(const char * name)
{
	const char * value = std::getenv(name);
	if (value == nullptr or value[0] != '/')
		return nullptr;
	return value;
}

std::filesystem::path home_subdir(const char * subdir)
{
	if (const char * home = absolute_env("HOME"))
		return std::filesystem::path(home) / subdir;

	return ".";
}

// Colon-separated list: relative entries are ignored, and so is a list with no usable entry.
std::vector<std::filesystem::path> path_list(const char * name, std::vector<std::filesystem::path> fallback)
{
	std::vector<std::filesystem::path> paths;
	if (const char * value = std::getenv(name))
	{
		for (const auto & path: utils::split(value, ":"))
		{
			if (path.starts_with('/'))
				paths.push_back(path);
		}
	}

	if (paths.empty())
		return fallback;
	return paths;
}
} // namespace

std::filesystem::path xdg_config_home()
{
	if (const char * xdg_config_home = absolute_env("XDG_CONFIG_HOME"))
		return xdg_config_home;

	return home_subdir(".config");
}

std::filesystem::path xdg_cache_home()
{
	if (const char * xdg_cache_home = absolute_env("XDG_CACHE_HOME"))
		return xdg_cache_home;

	return home_subdir(".cache");
}

std::filesystem::path xdg_data_home()
{
	if (const char * xdg_data_home = absolute_env("XDG_DATA_HOME"))
		return xdg_data_home;

	return home_subdir(".local/share");
}

std::filesystem::path xdg_runtime_dir()
{
	if (const char * xdg_runtime_dir = absolute_env("XDG_RUNTIME_DIR"))
		return xdg_runtime_dir;

	// tools/perfetto/wivrn_capture.py and docs/profiling.md rely on this fallback
	return "/tmp";
}

std::vector<std::filesystem::path> xdg_config_dirs()
{
	return path_list("XDG_CONFIG_DIRS", {"/etc/xdg"});
}

std::vector<std::filesystem::path> xdg_data_dirs(bool include_data_home)
{
	std::vector<std::filesystem::path> paths;
	if (include_data_home)
		paths.push_back(xdg_data_home());

	for (auto & path: path_list("XDG_DATA_DIRS", {"/usr/local/share", "/usr/share"}))
		paths.push_back(std::move(path));

	return paths;
}
