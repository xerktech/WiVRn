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

// fenrir front doors in the lobby: add one, pair it once by code, then list, launch and stop its
// VR Apps. The launched session's WiVRn server key comes from the authenticated API and is pinned
// for the stream (wivrn_session's pinned_identity), so no PIN is asked.

#include "application.h"
#include "fenrir.h"
#include "imgui.h"
#include "lobby.h"
#include "render/ui_theme.h"
#include "render/ui_widgets.h"
#include "utils/i18n.h"

#include "IconsFontAwesome7.h"
#include <algorithm>
#include <chrono>
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <thread>

using namespace std::chrono_literals;

namespace
{
std::filesystem::path store_path()
{
	return application::get_config_path() / "fenrir.json";
}

using token_t = utils::async_token<scenes::lobby::fenrir_result, scenes::lobby::fenrir_progress>;

const std::atomic<bool> * cancel_flag(token_t & token)
{
	return &token.shared_state->cancelled;
}

// Sleep, waking early when cancelled
void wait(token_t & token, std::chrono::milliseconds d)
{
	auto end = std::chrono::steady_clock::now() + d;
	while (std::chrono::steady_clock::now() < end)
	{
		if (token.is_cancelled())
			throw fenrir::api_error(0, "cancelled");
		std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(100ms, end - std::chrono::steady_clock::now()));
	}
}

// Apps, their covers and the current session
scenes::lobby::fenrir_result load(token_t & token, const fenrir::server & srv)
{
	fenrir::client c{srv, cancel_flag(token)};
	scenes::lobby::fenrir_result r;
	token.set_progress({.status = _("Loading the game list")});
	r.apps = c.apps();
	for (const auto & a: r.apps)
	{
		if (a.cover.empty())
			continue;
		try
		{
			r.covers.emplace_back(a.id, c.cover(a.cover));
		}
		catch (fenrir::api_error & e)
		{
			if (token.is_cancelled())
				throw;
			spdlog::warn("fenrir: no cover for {}: {}", a.id, e.what());
		}
	}
	r.session = c.get_session();
	return r;
}

scenes::lobby::fenrir_result pair(token_t & token, fenrir::server srv, std::string wivrn_key, std::string name)
{
	fenrir::client c{srv, cancel_flag(token)};
	token.set_progress({.status = _("Contacting the server")});

	auto nonce = fenrir::random_nonce();
	auto commitment = fenrir::sha256({reinterpret_cast<const char *>(nonce.data()), nonce.size()});

	// The front door hands out a pairing every 5 s at most, server-wide: wait for a turn
	fenrir::pair_reply reply;
	for (int attempt = 0;; ++attempt)
	{
		try
		{
			reply = c.pair(wivrn_key, name, commitment);
			break;
		}
		catch (fenrir::api_error & e)
		{
			// Already paired on fenrir while this entry says otherwise (cancel racing the
			// confirm, a lost save): if the pinned key admits this headset, it is paired
			if (e.status == 409 and not srv.server_key_sha256.empty())
			{
				try
				{
					c.apps();
					auto key = *fenrir::from_hex(srv.server_key_sha256); // checked by store::load
					scenes::lobby::fenrir_result r;
					std::copy_n(key.begin(), r.server_key.size(), r.server_key.begin());
					return r;
				}
				catch (fenrir::api_error &)
				{}
			}
			if ((e.status != 429 and e.status != 503) or attempt >= 20)
				throw;
			token.set_progress({.status = _("The server is busy pairing, waiting for a turn")});
			int seconds = e.status == 429 ? std::atoi(e.what()) : 15;
			wait(token, std::chrono::seconds(std::clamp(seconds, 1, 60)));
		}
	}

	auto code = fenrir::pairing_code(reply.server_key, fenrir::certificate_key_sha256(srv.tls_cert), wivrn_key, reply.server_nonce, nonce);
	token.set_progress({.status = _("Waiting for the code to be entered"), .code = code, .url = reply.pairing_url});

	try
	{
		c.confirm(reply.server_key, reply.pairing_id, nonce);
	}
	catch (fenrir::api_error & e)
	{
		// A confirm dropped mid-wait may still have paired: ask with the key it was made with
		if (e.status != 0 or token.is_cancelled())
			throw;
		srv.server_key_sha256 = fenrir::to_hex(reply.server_key);
		fenrir::client check{srv, cancel_flag(token)};
		try
		{
			check.apps();
		}
		catch (fenrir::api_error &)
		{
			throw e;
		}
	}

	return {.server_key = reply.server_key};
}

scenes::lobby::fenrir_result launch(token_t & token, fenrir::server srv, std::string app_id, std::string title)
{
	fenrir::client c{srv, cancel_flag(token)};
	token.set_progress({.status = fmt::format(_F("Starting {}"), title)});

	auto start = std::chrono::steady_clock::now();
	fenrir::session s = c.launch(app_id);
	while (s.state != "ready")
	{
		auto elapsed = std::chrono::steady_clock::now() - start;
		if (s.state == "other")
			throw fenrir::api_error(409, _("A Moonlight session is running on this account. End it first."));
		// A launch the server has not seen yet reads "none" for a moment
		if ((s.state == "none" or s.state == "stopping") and elapsed > 15s)
			throw fenrir::api_error(0, s.message.empty() ? _("The session stopped before it was ready.") : s.message);
		if (elapsed > 5min)
			throw fenrir::api_error(0, _("The session took too long to start."));

		std::string status = fmt::format(_F("Starting {} ({} s)"), title, std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
		if (not s.message.empty())
			status += "\n" + s.message;
		token.set_progress({.status = status});

		wait(token, 1s);
		s = c.get_session();
	}
	return {.session = s};
}

scenes::lobby::fenrir_result stop(token_t & token, fenrir::server srv)
{
	token.set_progress({.status = _("Stopping the game")});
	fenrir::client{srv, cancel_flag(token)}.stop();
	return load(token, srv);
}

std::string error_text(const fenrir::api_error & e, const std::string & server_name)
{
	switch (e.status)
	{
		case 401:
			return fmt::format(_F("This headset is no longer paired with {}: it was revoked, or never finished pairing. Pair it again."), server_name);
		case 408:
			return _("Nobody entered the code in time. Start pairing again.");
		case 409:
			return fmt::format(_F("Busy: {}"), e.what());
		default:
			return e.what();
	}
}
} // namespace

fenrir::server * scenes::lobby::fenrir_server()
{
	if (not fenrir_store)
		return nullptr;
	return fenrir_store->find(fenrir_current);
}

bool scenes::lobby::fenrir_save()
{
	if (not fenrir_store)
		return false;
	try
	{
		fenrir_store->save(store_path());
		return true;
	}
	catch (std::exception & e)
	{
		spdlog::error("Cannot save {}: {}", store_path().native(), e.what());
		fenrir_error = fenrir::api_error(0, fmt::format(_F("Cannot save the fenrir servers: {}"), e.what()));
		return false;
	}
}

void scenes::lobby::fenrir_clear_covers()
{
	for (auto & [id, tex]: fenrir_covers)
		imgui_ctx->free_texture(tex);
	fenrir_covers.clear();
}

void scenes::lobby::fenrir_start(fenrir_op_kind kind, std::string app_id)
{
	fenrir::server * srv = fenrir_server();
	if (not srv)
		return;

	fenrir_op.cancel();
	fenrir_error.reset();
	fenrir_key_check.reset();
	fenrir_key_rejected = false;
	fenrir_op_running = kind;

	using R = fenrir_result;
	using P = fenrir_progress;
	switch (kind)
	{
		case fenrir_op_kind::none:
			fenrir_op_running = fenrir_op_kind::none;
			break;
		case fenrir_op_kind::pairing:
			fenrir_op = utils::async<R, P>(
			        [](auto token, fenrir::server srv, std::string key, std::string name) { return pair(token, srv, key, name); },
			        fenrir::server{*srv},
			        fenrir::wivrn_key_body(keypair.public_key()),
			        application::get_hmd_traits().model_name());
			break;
		case fenrir_op_kind::loading:
			fenrir_op = utils::async<R, P>([](auto token, fenrir::server srv) { return load(token, srv); }, fenrir::server{*srv});
			break;
		case fenrir_op_kind::launching: {
			std::string title = app_id;
			for (const auto & a: fenrir_apps)
				if (a.id == app_id)
					title = a.title;
			fenrir_op = utils::async<R, P>(
			        [](auto token, fenrir::server srv, std::string id, std::string title) { return launch(token, srv, id, title); },
			        fenrir::server{*srv},
			        std::string{app_id},
			        std::string{title});
			break;
		}
		case fenrir_op_kind::stopping:
			fenrir_op = utils::async<R, P>([](auto token, fenrir::server srv) { return stop(token, srv); }, fenrir::server{*srv});
			break;
	}
}

void scenes::lobby::fenrir_poll()
{
	if (not fenrir_op.valid() or fenrir_op.poll() != utils::future_status::ready)
		return;

	auto kind = std::exchange(fenrir_op_running, fenrir_op_kind::none);
	fenrir::server * srv = fenrir_server();
	try
	{
		fenrir_result r = fenrir_op.get();
		fenrir_op.reset();
		if (not srv)
			return;

		switch (kind)
		{
			case fenrir_op_kind::none:
				break;

			case fenrir_op_kind::pairing:
				// Nothing pinned before this pairing: whoever answered may not be fenrir. Pin
				// only once the user matched the key with fenrir's pairing page.
				if (srv->server_key_sha256.empty())
				{
					fenrir_key_check = r.server_key;
					break;
				}
				srv->server_key_sha256 = fenrir::to_hex(r.server_key);
				srv->paired = true;
				// Keep the save error on screen: the pairing would be lost at restart
				if (fenrir_save())
					fenrir_start(fenrir_op_kind::loading);
				break;

			case fenrir_op_kind::loading:
			case fenrir_op_kind::stopping:
				fenrir_clear_covers();
				fenrir_apps = std::move(r.apps);
				fenrir_session = std::move(r.session);
				for (auto & [id, png]: r.covers)
				{
					try
					{
						fenrir_covers.emplace(id, imgui_ctx->load_texture(std::span<const std::byte>{png}, "fenrir-" + id));
					}
					catch (std::exception & e)
					{
						spdlog::warn("fenrir: cannot load the cover of {}: {}", id, e.what());
					}
				}
				break;

			case fenrir_op_kind::launching: {
				fenrir_session = r.session;
				configuration::server_data data{
				        .autoconnect = false,
				        .manual = true,
				        .visible = true,
				        .compatible = true,
				        .service = {
				                .name = r.session.title.empty() ? srv->name : r.session.title,
				                .hostname = r.session.host,
				                .port = r.session.port,
				                .tcp_only = false,
				        },
				};
				fenrir_current.clear();
				ImGui::CloseCurrentPopup();
				// The key fenrir reported over the paired, pinned API: the stream needs no PIN
				connect(data, r.session.server_key);
				break;
			}
		}
	}
	catch (fenrir::api_error & e)
	{
		fenrir_op.reset();
		if (std::string_view{e.what()} != "cancelled")
		{
			spdlog::warn("fenrir: {}", e.what());
			fenrir_error = e;
		}
	}
	catch (std::exception & e)
	{
		fenrir_op.reset();
		spdlog::warn("fenrir: {}", e.what());
		fenrir_error = fenrir::api_error(0, e.what());
	}
}

void scenes::lobby::gui_fenrir_add()
{
	namespace ui = wivrn::ui;
	const float w = ImGui::GetContentRegionAvail().x;

	ImGui::TextUnformatted(_S("Name"));
	if (ImGui::IsWindowAppearing())
		ImGui::SetKeyboardFocusHere();
	ui::input_text("##fenrir_name", fenrir_add_name, _cS("placeholder for the fenrir server name", "fenrir"), w);
	ImGui::Dummy({0, 6});

	ImGui::TextUnformatted(_S("Address"));
	ui::input_text("##fenrir_host", fenrir_add_host, _cS("placeholder for the fenrir server address", "192.168.1.10 or fenrir.local"), w);
	ImGui::Dummy({0, 6});

	ImGui::TextUnformatted(_S("Port"));
	ui::input_int("##fenrir_port", &fenrir_add_port, 1, 0, 65535, w);
	ImGui::Dummy({0, 12});

	const float gap = ImGui::GetStyle().ItemSpacing.x;
	const std::string cancel_l = _("Cancel");
	const std::string pair_l = _("Pair");
	const float cancel_w = ui::button_width(cancel_l);
	const float pair_w = ui::button_width(pair_l);
	ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - cancel_w - pair_w - gap);

	if (ui::button(cancel_l, ui::button_style::secondary, {cancel_w, 0}))
		ImGui::CloseCurrentPopup();
	ImGui::SameLine();
	ImGui::BeginDisabled(fenrir_add_host.empty() or fenrir_add_port < 1 or fenrir_add_port > 65535 or not fenrir_store);
	if (ui::button(pair_l, ui::button_style::primary, {pair_w, 0}))
	{
		try
		{
			auto identity = fenrir::make_tls_identity();
			fenrir::server srv{
			        .id = fenrir::random_id(),
			        .name = fenrir_add_name.empty() ? fenrir_add_host : fenrir_add_name,
			        .host = fenrir_add_host,
			        .port = fenrir_add_port,
			        .tls_key = std::move(identity.key),
			        .tls_cert = std::move(identity.cert),
			};
			fenrir_current = srv.id;
			fenrir_store->servers.push_back(std::move(srv));
			fenrir_save();
			fenrir_apps.clear();
			fenrir_session.reset();
			fenrir_clear_covers();
			fenrir_start(fenrir_op_kind::pairing);
		}
		catch (std::exception & e)
		{
			spdlog::error("fenrir: cannot create the TLS identity: {}", e.what());
			fenrir_error = fenrir::api_error(0, e.what());
		}
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndDisabled();
}

void scenes::lobby::gui_fenrir_window()
{
	namespace ui = wivrn::ui;
	const ImGuiStyle & style = ImGui::GetStyle();
	const auto & t = ui::current();

	fenrir_poll();
	fenrir::server * srv = fenrir_server();
	if (not srv)
	{
		fenrir_op.cancel();
		fenrir_op_running = fenrir_op_kind::none;
		ImGui::CloseCurrentPopup();
		return;
	}

	ImGui::Dummy({640, 0});
	ImGui::PushFont(nullptr, style.FontSizeBase * ui::metrics::font_modal_title);
	ImGui::TextUnformatted(srv->name.c_str());
	ImGui::PopFont();
	ImGui::Dummy({0, style.ItemSpacing.y});

	auto right_buttons = [&](const std::vector<std::pair<std::string, ui::button_style>> & buttons) {
		const float gap = style.ItemSpacing.x;
		float total = 0;
		for (const auto & [label, s]: buttons)
			total += ui::button_width(label) + gap;
		ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - total + gap);
		int clicked = -1;
		for (size_t i = 0; i < buttons.size(); ++i)
		{
			if (i)
				ImGui::SameLine();
			if (ui::button(buttons[i].first, buttons[i].second, {ui::button_width(buttons[i].first), 0}))
				clicked = i;
		}
		return clicked;
	};

	auto close = [&] {
		fenrir_op.cancel();
		fenrir_op_running = fenrir_op_kind::none;
		fenrir_key_check.reset();
		fenrir_key_rejected = false;
		fenrir_current.clear();
		ImGui::CloseCurrentPopup();
	};

	// An operation in flight: its progress, and the pairing code once known
	if (fenrir_op.valid())
	{
		fenrir_progress p = fenrir_op.get_progress();
		if (not p.code.empty())
		{
			ImGui::TextWrapped("%s", p.url.empty() ? _S("Enter this code on fenrir's VR headset pairing page:") : fmt::format(_F("Enter this code at {}"), p.url).c_str());
			ImGui::Dummy({0, 12});
			ImGui::PushFont(nullptr, style.FontSizeBase * 3);
			const std::string code = fenrir::format_code(p.code);
			ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(code.c_str()).x) / 2);
			ImGui::TextUnformatted(code.c_str());
			ImGui::PopFont();
			ImGui::Dummy({0, 12});
		}
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextWrapped("%s", p.status.c_str());
		ImGui::PopStyleColor();
		ImGui::Dummy({0, 12});

		const bool launching = fenrir_op_running == fenrir_op_kind::launching;
		std::vector<std::pair<std::string, ui::button_style>> buttons{{_("Cancel"), ui::button_style::secondary}};
		if (launching)
			buttons.emplace_back(ui::icon_label(ICON_FA_STOP, _("Stop game")), ui::button_style::danger);
		switch (right_buttons(buttons))
		{
			case 0: {
				auto kind = std::exchange(fenrir_op_running, fenrir_op_kind::none);
				fenrir_op.cancel();
				if (not srv->paired)
					close();
				else if (kind == fenrir_op_kind::pairing)
					fenrir_start(fenrir_op_kind::loading); // back to the list, or to its error
				break;
			}
			case 1:
				fenrir_start(fenrir_op_kind::stopping);
				break;
		}
		return;
	}

	// A first pairing finished: the user matches the key with fenrir's pairing page before it is
	// pinned. The code alone proves nothing here, as a fake front door computes it too.
	if (fenrir_key_check)
	{
		ImGui::TextWrapped("%s", _S("Check this server's key. fenrir's VR headset pairing page shows its key: it must be exactly this one."));
		ImGui::Dummy({0, 12});
		const std::string fp = fenrir::key_fingerprint(*fenrir_key_check);
		ImGui::PushFont(nullptr, style.FontSizeBase * 2);
		for (const std::string & line: {fp.substr(0, 19), fp.substr(20)})
		{
			ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(line.c_str()).x) / 2);
			ImGui::TextUnformatted(line.c_str());
		}
		ImGui::PopFont();
		ImGui::Dummy({0, 12});
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextWrapped("%s", _S("If any group differs, something on your network answered instead of fenrir: do not use it."));
		ImGui::PopStyleColor();
		ImGui::Dummy({0, 12});
		switch (right_buttons({{_("Keys differ"), ui::button_style::danger}, {_("Keys match"), ui::button_style::primary}}))
		{
			case 0:
				fenrir_key_check.reset();
				fenrir_key_rejected = true;
				break;
			case 1:
				srv->server_key_sha256 = fenrir::to_hex(*fenrir_key_check);
				srv->paired = true;
				fenrir_key_check.reset();
				// Keep the save error on screen: the pairing would be lost at restart
				if (fenrir_save())
					fenrir_start(fenrir_op_kind::loading);
				break;
		}
		return;
	}

	if (fenrir_key_rejected)
	{
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextWrapped("%s %s", ICON_FA_CIRCLE_EXCLAMATION, _S("Not paired: that key was not fenrir's. Check the address, then pair again."));
		ImGui::PopStyleColor();
		ImGui::Dummy({0, 12});
	}

	if (fenrir_error)
	{
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextWrapped("%s %s", ICON_FA_CIRCLE_EXCLAMATION, error_text(*fenrir_error, srv->name).c_str());
		ImGui::PopStyleColor();
		ImGui::Dummy({0, 12});
	}

	if (not srv->paired or (fenrir_error and fenrir_error->status == 401))
	{
		switch (right_buttons({{_("Close"), ui::button_style::secondary}, {ui::icon_label(ICON_FA_LINK, _("Pair")), ui::button_style::primary}}))
		{
			case 0:
				close();
				break;
			case 1:
				fenrir_start(fenrir_op_kind::pairing);
				break;
		}
		return;
	}

	// Game list
	if (fenrir_session and fenrir_session->state != "none")
	{
		std::string what = fenrir_session->state == "other" ? _("A Moonlight session is running on this account.")
		                                                    : fmt::format(_F("Running: {}"), fenrir_session->title.empty() ? fenrir_session->app : fenrir_session->title);
		ui::chip(what, ui::chip_style::accent);
		ImGui::Dummy({0, 6});
	}

	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ui::metrics::card_item_spacing);
	ImGui::BeginChild("##fenrir_apps", {0, 520});
	ui::begin_list_card("##fenrir_apps_card");
	if (fenrir_apps.empty())
	{
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextWrapped("%s", _S("No VR games on this account."));
		ImGui::PopStyleColor();
	}
	bool first = true;
	std::string to_launch;
	for (const auto & a: fenrir_apps)
	{
		ImGui::PushID(a.id.c_str());
		if (not first)
			ui::row_separator();
		first = false;
		auto cover = fenrir_covers.find(a.id);
		const auto row = ui::begin_list_row("##app", ICON_FA_GAMEPAD, cover == fenrir_covers.end() ? ImTextureID{} : cover->second, a.title, {}, false, 0, 0, true);
		if (row.clicked)
			to_launch = a.id;
		ui::end_list_row();
		ImGui::PopID();
	}
	ui::end_card();
	ImGui::EndChild();
	ImGui::PopStyleVar();
	ImGui::Dummy({0, 12});

	if (not to_launch.empty())
	{
		fenrir_start(fenrir_op_kind::launching, to_launch);
		return;
	}

	std::vector<std::pair<std::string, ui::button_style>> buttons{
	        {_("Close"), ui::button_style::secondary},
	        {ui::icon_label(ICON_FA_ARROWS_ROTATE, _("Refresh")), ui::button_style::secondary},
	};
	const bool running = fenrir_session and fenrir_session->state != "none" and fenrir_session->state != "other";
	if (running)
		buttons.emplace_back(ui::icon_label(ICON_FA_STOP, _("Stop game")), ui::button_style::danger);
	switch (right_buttons(buttons))
	{
		case 0:
			close();
			break;
		case 1:
			fenrir_start(fenrir_op_kind::loading);
			break;
		case 2:
			fenrir_start(fenrir_op_kind::stopping);
			break;
	}
}

void scenes::lobby::gui_fenrir_servers()
{
	namespace ui = wivrn::ui;
	const auto & t = ui::current();

	if (not fenrir_loaded)
	{
		fenrir_loaded = true;
		try
		{
			fenrir_store = fenrir::store::load(store_path());
		}
		catch (std::exception & e)
		{
			spdlog::error("Cannot read {}: {}", store_path().native(), e.what());
			fenrir_store_error = e.what();
		}
	}

	ImGui::Dummy({0, 18});
	const ImVec2 hstart = ImGui::GetCursorPos();
	const float header_avail = ImGui::GetContentRegionAvail().x;
	ui::page_header(_cS("page header title", "fenrir"), _cS("page header subtitle", "Pair once with a code, then pick a VR game here."));
	const ImVec2 hend = ImGui::GetCursorPos();

	bool open_add = false;
	bool open_window = false;
	bool open_delete = false;

	const std::string add_label = _("Add fenrir server");
	const float add_w = ui::button_width(ICON_FA_PLUS, add_label);
	ImGui::SetCursorPos({hstart.x + header_avail - add_w, hstart.y});
	ImGui::BeginDisabled(not fenrir_store);
	if (ui::button(ICON_FA_PLUS, add_label, ui::button_style::secondary))
	{
		fenrir_add_name.clear();
		fenrir_add_host.clear();
		fenrir_add_port = 0;
		open_add = true;
	}
	ImGui::EndDisabled();
	ImGui::SetCursorPos(hend);

	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ui::metrics::card_item_spacing);
	ui::begin_list_card("##fenrir_servers");
	if (not fenrir_store)
	{
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextWrapped("%s", fmt::format(_F("Cannot read the fenrir servers, they are left untouched: {}"), fenrir_store_error).c_str());
		ImGui::PopStyleColor();
	}
	else if (fenrir_store->servers.empty())
	{
		ImGui::PushStyleColor(ImGuiCol_Text, t.text_muted);
		ImGui::TextUnformatted(_S("Add a fenrir server to play its VR games."));
		ImGui::PopStyleColor();
	}
	else
	{
		bool first = true;
		for (auto & srv: fenrir_store->servers)
		{
			ImGui::PushID(srv.id.c_str());
			if (not first)
				ui::row_separator();
			first = false;

			const float gap = ImGui::GetStyle().ItemSpacing.x;
			const float bh = ImGui::GetFrameHeight() * ui::metrics::control_height;
			const std::string c_label = srv.paired ? ui::icon_label(ICON_FA_GAMEPAD, _("Games")) : ui::icon_label(ICON_FA_LINK, _("Pair"));
			const float cw = ui::button_width(c_label);
			const std::string sub = fmt::format("{} : {}{}", srv.host, srv.port, srv.paired ? "" : _(" (not paired)"));

			const auto row = ui::begin_list_row("##row", ICON_FA_VR_CARDBOARD, 0, srv.name, sub, false, bh + gap + cw + ui::metrics::list_row_pad);
			float x = row.max.x;

			const std::string del_l = _C("item in action menu", "Delete server");
			ImGui::SetCursorScreenPos(row.trailing(x, {bh, bh}));
			if (ui::action_menu("##menu", ICON_FA_ELLIPSIS_VERTICAL, {{ICON_FA_TRASH, del_l.c_str(), true, false}}) == 0)
			{
				fenrir_delete = srv.id;
				open_delete = true;
			}
			x -= bh + gap;

			ImGui::SetCursorScreenPos(row.trailing(x, {cw, bh}));
			if (ui::button(c_label, ui::button_style::primary, {cw, 0}))
			{
				fenrir_current = srv.id;
				fenrir_apps.clear();
				fenrir_session.reset();
				fenrir_clear_covers();
				fenrir_start(srv.paired ? fenrir_op_kind::loading : fenrir_op_kind::pairing);
				open_window = true;
			}

			ui::end_list_row();
			ImGui::PopID();
		}
	}
	ui::end_card();
	ImGui::PopStyleVar();

	// Pairing started from the add window
	if (not fenrir_current.empty() and not ImGui::IsPopupOpen("fenrir") and not ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopup))
		open_window = true;

	if (open_add)
		ImGui::OpenPopup("add fenrir server");
	if (open_window)
		ImGui::OpenPopup("fenrir");
	if (open_delete)
		ImGui::OpenPopup("delete fenrir server");

	if (ui::begin_modal("add fenrir server", _C("popup window title", "Add fenrir server"), 620))
	{
		gui_fenrir_add();
		ui::end_modal();
	}

	if (ui::begin_modal("fenrir", ""))
	{
		gui_fenrir_window();
		ui::end_modal();
	}

	if (not fenrir_delete.empty() and fenrir_store)
	{
		std::string name;
		if (auto * srv = fenrir_store->find(fenrir_delete))
			name = srv->name;

		switch (ui::confirm_modal("delete fenrir server", _C("confirmation messagebox title", "Delete server"), fmt::format(_cF("confirmation message", "Forget \"{}\"? Using it again needs a new pairing."), name), _("Delete"), _("Cancel"), true))
		{
			case 1:
				std::erase_if(fenrir_store->servers, [&](const fenrir::server & s) { return s.id == fenrir_delete; });
				fenrir_save();
				fenrir_delete.clear();
				break;
			case -1:
				fenrir_delete.clear();
				break;
		}
	}
}
