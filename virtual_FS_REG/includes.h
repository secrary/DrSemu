#pragma once

// prevent redefinition of NTSTATUS messages
#define UMDF_USING_NTSTATUS

// http://www.suodenjoki.dk/us/archive/2010/min-max.htm
#define NOMINMAX

#define PHNT_VERSION PHNT_THRESHOLD // Windows 10
#include "phnt_windows.h"
#include "phnt.h"
#include <psapi.h>
#pragma comment(lib, "ntdll.lib")
#include <objbase.h>    // For CoCreateGuid

#include <ntstatus.h>

// STL
#include <string>
#include <filesystem>
namespace fs = std::filesystem;
#include <map>
#include <vector>
#include <algorithm>
#include <memory>
#include <atomic>
#include <fstream>
#include <vector>

// Windows SDK
#include <projectedfslib.h>
#pragma comment(lib, "ProjectedFSLib")

#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "shared_config.h"

#include "dir_info.h"
#include "virtualizationInstance.h"

#include "fs_provider.h"

const std::wstring instance_id_file = LR"(\.fsId)";
