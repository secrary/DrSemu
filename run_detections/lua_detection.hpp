#pragma once

#include "includes.h"

#include "../DrSemu/shared.hpp"

namespace lua_scan
{
	inline bool check_lua(lua_State* lua_state, const int error_code)
	{
		if (error_code != LUA_OK)
		{
			const std::string error_msg = lua_tostring(lua_state, -1);
			printf("[check_lua] msg: %s\n", error_msg.c_str());
			return false;
		}
		return true;
	}

	inline std::string run_rule(const std::string& lua_script, const std::string& json_path)
	{
		const auto lua_state{luaL_newstate()};

		// add standard libs
		luaL_openlibs(lua_state);

		if (check_lua(lua_state, luaL_dofile(lua_state, lua_script.c_str())))
		{
			lua_getglobal(lua_state, "check");
			if (lua_isfunction(lua_state, -1))
			{
				lua_pushstring(lua_state, json_path.c_str());
				if (check_lua(lua_state, lua_pcall(lua_state, 1, 1, 0)))
				{
					if (lua_isstring(lua_state, -1) != 0)
					{
						const std::string result = lua_tostring(lua_state, -1);
						lua_close(lua_state);
						return result;
					}
				}
			}
		}

		lua_close(lua_state);
		return {};
	}


	inline std::string lua_rules_verdict(const std::wstring& report_directory,
	                                     const fs::path& rules_directory, const std::wstring& current_location,
	                                     const dr_semu::shared::slot& report_slot)
	{
		/// lua rules
		// save json.lua file from https://github.com/rxi/json.lua under current_loc\lua\json.lua
		// otherwise it downloads from the Github
		const fs::path lua_json_path{current_location + LR"(lua\json.lua)"};
		if (!exists(lua_json_path))
		{
			const auto lua_dir = lua_json_path.parent_path();
			if (!exists(lua_dir))
			{
				create_directory(lua_dir);
			}
			const std::wstring lua_json_github{LR"(https://raw.githubusercontent.com/rxi/json.lua/master/json.lua)"};
			if (S_OK != URLDownloadToFile(nullptr, lua_json_github.c_str(), lua_json_path.c_str(), 0, nullptr))
			{
				printf(
					"Failed to download json.lua [https://github.com/rxi/json.lua]\nAborting...\n\
			Download https://raw.githubusercontent.com/rxi/json.lua/master/json.lua manually and place under \"lua\" folder\n");
				const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::FAILED);
				return {};
			}
		}
		// iterate rules

		if (!exists(rules_directory))
		{
			create_directory(rules_directory);
			printf("lua_rules directory is empty: %ls\n", rules_directory.wstring().c_str());
			const auto slot_result = report_slot.write_slot(dr_semu::shared::constants::SUCCEED);
			return {};
		}

		std::string verdict_string{};
		const std::string report_directory_ascii(report_directory.begin(), report_directory.end());
		for (auto& lua_script : fs::directory_iterator(rules_directory))
		{
			if (lua_script.path().extension() == L".lua")
			{
				verdict_string = run_rule(lua_script.path().string(), report_directory_ascii);
				if (!verdict_string.empty() && verdict_string != "CLEAN")
				{
					return verdict_string;
				}
			}
		}
		return verdict_string;
	}
} // namespace lua_scan
