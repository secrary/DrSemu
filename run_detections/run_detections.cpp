#include "includes.h"

#include "lua_detection.hpp"
#include "../DrSemu/shared.hpp"

std::wstring get_current_location()
{
	TCHAR cur_loc[MAX_PATH]{};
	const auto result_size = GetModuleFileName(nullptr, cur_loc, MAX_PATH);

	const std::wstring current_location(cur_loc, result_size);
	return fs::path(current_location).remove_filename().wstring();
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 2)
	{
		printf(R"(Usage: run_detections.exe path/to/report_directory result_mailslot_name)");
		MessageBox(nullptr, nullptr, nullptr, 0);
		return -1;
	}

	const std::wstring slot_name = argv[1];
	const dr_semu::shared::slot report_slot(slot_name, false);
	if (!report_slot.is_valid())
	{
		printf("[run_detections] failed to open a slot: %ls\n", slot_name.c_str());
		return -1;
	}

	const auto current_location = get_current_location();

	const std::wstring report_directory = argv[0];
	const auto json_path_starter = report_directory + L"\\" + L"starter.json";
	const std::string report_directory_ascii(report_directory.begin(), report_directory.end());
	if (!fs::exists(json_path_starter))
	{
		printf("[run_detections] failed to locate starter.json file\npath: %ls\n", json_path_starter.c_str());
		const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::FAILED);
		return -1;
	}

	/// lua rules
	// save json.lua file from https://github.com/rxi/json.lua under current_loc\lua\json.lua
	// otherwise it downloads from the Github
	fs::path lua_json_path{current_location + LR"(lua\json.lua)"};
	if (!exists(lua_json_path))
	{
		const auto lua_dir = lua_json_path.parent_path();
		if (!exists(lua_dir))
		{
			create_directory(lua_dir);
		}
		std::wstring lua_json_github{LR"(https://raw.githubusercontent.com/rxi/json.lua/master/json.lua)"};
		if (S_OK != URLDownloadToFile(nullptr, lua_json_github.c_str(), lua_json_path.c_str(), 0, nullptr))
		{
			printf(
				"Failed to download json.lua [https://github.com/rxi/json.lua]\nAborting...\n\
			Download https://raw.githubusercontent.com/rxi/json.lua/master/json.lua manually and place under \"lua\" folder\n");
			const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::FAILED);
			return -1;
		}
	}
	// iterate rules
	fs::path lua_rules{current_location + L"lua_rules"};
	if (!exists(lua_rules))
	{
		create_directory(lua_rules);
		printf("lua_rules directory is empty: %ls\n", lua_rules.wstring().c_str());
		const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::SUCCEED);
		return 0;
	}

	std::string verdict_string{};
	for (auto& lua_script : fs::directory_iterator(lua_rules))
	{
		if (lua_script.path().extension() == L".lua")
		{
			verdict_string = lua_scan::run_rule(lua_script.path().string(), report_directory_ascii);
			if (!verdict_string.empty() && verdict_string != "CLEAN")
			{
				break;
			}
		}
	}
	if (verdict_string.empty())
	{
		verdict_string = "NO DETECTIONS";
	}
	const auto verdict_wide = std::wstring(verdict_string.begin(), verdict_string.end());
	const auto slot_result = report_slot.write_slot(verdict_wide);


	return 0;
}
