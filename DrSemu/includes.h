#pragma once

// prevent redefinition of NTSTATUS messages
#define UMDF_USING_NTSTATUS

// http://www.suodenjoki.dk/us/archive/2010/min-max.htm
#define NOMINMAX

#define WINDOWS

#ifdef _WIN64
#define X86_64
#else
#define X86_32
#endif

#pragma warning(disable : 4100) // unreferenced formal parameter
#pragma warning(disable : 4189) // local variable is initialized but not referenced
#pragma warning(disable : 4996) // concurrent_unordered_set.h error


#define PHNT_VERSION PHNT_THRESHOLD // Windows 10
#include <phnt_windows.h>
#include <phnt.h>
#include "win_internal.h" // definitions missed in phnt

#include <filesystem>
namespace fs = std::filesystem;

#include <unordered_map>
#include <unordered_set>
#include <tuple>
#include <string>
#include <array>
#include <vector>
#include <algorithm>
#include <strsafe.h>
#include <winsock.h>
#include <urlmon.h>

#include <concurrent_vector.h>
#include <concurrent_unordered_set.h>
using namespace concurrency;

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#pragma warning(disable : 4146)
#include <LIEF/LIEF.h>

#include "../virtual_FS_REG/shared_config.h"

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"

#include "shared.hpp"
#include "utils.hpp"
#include "networking_handlers.hpp"
