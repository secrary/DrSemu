#pragma once
#define NOMINMAX

#include <iostream>
#include <memory>
#include <Windows.h>
#include <filesystem>
namespace fs = std::filesystem;


#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
#include "spdlog/spdlog.h"

#include "spdlog/sinks/basic_file_sink.h"
#include "lua.hpp"

#ifdef _WIN32
#pragma comment(lib, "lua53")
#pragma comment(lib, "Urlmon")
#endif // _WIN32
