#include "includes.h"

#include "lua_detection.hpp"
#include "python_detection.hpp"
#include "../DrSemu/shared.hpp"

inline std::wstring get_current_location()
{
	TCHAR cur_loc[MAX_PATH]{};
	const auto result_size = GetModuleFileName(nullptr, cur_loc, MAX_PATH);

	const std::wstring current_location(cur_loc, result_size);
	return fs::path(current_location).remove_filename().wstring();
}

int wmain(const int argc, wchar_t** argv)
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
		spdlog::error(L"[run_detections] failed to open a slot: {}\n", slot_name);
		return -1;
	}

	const std::wstring report_directory = argv[0];
	const auto json_path_starter = report_directory + L"\\" + L"starter.json";
	if (!fs::exists(json_path_starter))
	{
		spdlog::error(L"[run_detections] failed to locate starter.json file\npath: {}\n", json_path_starter);
		const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::FAILED);
		return {};
	}

	const auto current_location = get_current_location();
	const fs::path rules_directory{current_location + L"dr_rules"};
	if (!exists(rules_directory))
	{
		spdlog::error(L"[run_detections] failed to locate rules directory. path: {}\n", rules_directory.wstring());
		const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::FAILED);
		return {};
	}

	auto verdict_string = lua_scan::lua_rules_verdict(report_directory, rules_directory, current_location, report_slot);

	// Python
	if (verdict_string.empty() || verdict_string == "CLEAN")
	{
		const std::string report_directory_ascii(report_directory.begin(), report_directory.end());
		verdict_string = python_rules_verdict(rules_directory.string(), report_directory_ascii);
	}

	if (verdict_string.empty())
	{
		verdict_string = "NO DETECTIONS";
	}

	const auto verdict_wide = std::wstring(verdict_string.begin(), verdict_string.end());
	const auto slot_result = report_slot.write_slot(verdict_wide);

	return 0;
}
