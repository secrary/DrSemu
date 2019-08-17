#pragma once

#include <Windows.h>

inline BOOL create_reg_process(const std::wstring_view command)
{
	spdlog::info(L"cmd: {}", command);
	STARTUPINFO sa{sizeof(STARTUPINFO)};
	PROCESS_INFORMATION pi{};

	const auto status = CreateProcess(nullptr, LPWSTR(command.data()), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
	                                  &sa, &pi);
	if (status == 0)
	{
		return status;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD exit_code;
	GetExitCodeProcess(pi.hProcess, &exit_code);

	return exit_code == 0;
}
