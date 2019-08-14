#define PHNT_VERSION PHNT_THRESHOLD // Windows 10
#include "phnt_windows.h"
#include "phnt.h"
#pragma comment(lib, "ntdll")

#include "psapi.h"
#include <cstdio>
#include <string>
#include "../DrSemu/win_internal.h"

std::wstring get_image_path()
{
	TCHAR buf[MAX_PATH]{};
	GetModuleFileName(nullptr, buf, MAX_PATH);
	return buf;
}

std::wstring get_base_name()
{
	TCHAR buf[MAX_PATH]{};
	GetModuleBaseName(GetCurrentProcess(), nullptr, buf, MAX_PATH);
	return buf;
}

inline void change_command_line()
{
	const std::wstring explorer_path = L"C:\\Windows\\Explorer.EXE";

	const auto ptr_peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	const auto command_line = ptr_peb->ProcessParameters->CommandLine;

	memset(command_line.Buffer, 0, command_line.MaximumLength);

	memcpy_s(command_line.Buffer, command_line.MaximumLength, explorer_path.c_str(),
		explorer_path.length() * sizeof(TCHAR));
}

int wmain(const int argc, wchar_t** argv)
{
	//if (argc < 2)
	//{
	//	return -1;
	//}

	const std::wstring event_name = argv[1];

	//const auto current_image_path = get_image_path(); // GetModuleFileName parses PEB
	//const auto base_name = get_base_name(); // GetModuleBaseName parses Ldr to find a module (BaseDllName)

	// Dr.Semu changes everything for us except command line
	change_command_line();

	const auto wait_handle = OpenEvent(GENERIC_ALL, FALSE, event_name.c_str());

	if (wait_handle == nullptr)
	{
		MessageBox(nullptr, L"Failed to open a event", L"fake Explorer", 0);
	}

	const auto wait_result = WaitForSingleObject(wait_handle, INFINITE);

	return 0;
}
