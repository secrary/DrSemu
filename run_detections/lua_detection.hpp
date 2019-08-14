#pragma once

#include "includes.h"

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
		const auto lua_state{ luaL_newstate() };

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
} // namespace lua_scan
