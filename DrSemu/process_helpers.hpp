#pragma once

namespace dr_semu::process::helpers
{
	struct create_process_pre_info
	{
		std::string image_path_ascii{};
		std::string command_line_ascii{};
		bool is_x86{};
		bool is_suspended{};
		PHANDLE ptr_proc_handle{};
		PHANDLE ptr_thread_handle{};
	};

	inline std::unordered_map<size_t, create_process_pre_info> pre_create_process_tid{};

	//inline bool rtl_create_process(const std::wstring& application_name, const std::wstring& command_line,
	//                               const bool suspended = false)
	//{
	//	if (application_name.empty())
	//	{
	//		return false;
	//	}
	//
	//	UNICODE_STRING application;
	//	UNICODE_STRING cmd_line;
	//	RtlInitUnicodeString(&application, const_cast<PWSTR>(application_name.data()));
	//	RtlInitUnicodeString(&cmd_line, const_cast<PWSTR>(command_line.data()));
	//
	//	PRTL_USER_PROCESS_PARAMETERS user_parameters = nullptr;
	//	RTL_USER_PROCESS_INFORMATION process_info = {0};
	//
	//	if (NT_SUCCESS(
	//		RtlCreateProcessParameters(&user_parameters, &application, nullptr, nullptr, &cmd_line, nullptr, nullptr,
	//			nullptr, nullptr, nullptr)))
	//	{
	//		const auto parent_handle = OpenProcess(GENERIC_ALL, FALSE, GetCurrentProcessId());
	//		const auto status = RtlCreateUserProcess(&application, OBJ_CASE_INSENSITIVE, user_parameters, nullptr,
	//		                                         nullptr, parent_handle, FALSE, nullptr, nullptr, &process_info);
	//		if (NT_SUCCESS(status))
	//		{
	//			if (NT_SUCCESS(NtResumeThread(process_info.Thread, nullptr)))
	//			{
	//				return true;
	//			}
	//		}
	//		else
	//		{
	//			dr_printf("status: 0x%x\n", status);
	//		}
	//		RtlDestroyProcessParameters(user_parameters);
	//	}
	//
	//
	//	return false;
	//}

	inline std::wstring get_process_image_path(const HANDLE process_handle)
	{
		DWORD size = MAX_PATH;
		std::array<TCHAR, MAX_PATH> process_name{};
		QueryFullProcessImageName(process_handle, 0, process_name.data(), &size);

		return process_name.data();
	}

	inline std::wstring get_process_image_path(const DWORD process_id)
	{
		const auto process_handle = OpenProcess(
			PROCESS_QUERY_LIMITED_INFORMATION,
			FALSE,
			process_id
		);
		if (process_handle == INVALID_HANDLE_VALUE)
		{
			return {};
		}

		const auto process_name = get_process_image_path(process_handle);
		CloseHandle(process_handle);

		return process_name;
	}

	inline std::wstring get_process_name(const DWORD process_id) noexcept
	{
		const fs::path image_path = get_process_image_path(process_id);

		return image_path.filename().wstring();
	}

	inline std::wstring get_process_name(const HANDLE process_handle) noexcept
	{
		const fs::path image_path = get_process_image_path(process_handle);

		return image_path.filename().wstring();
	}

	inline DWORD get_process_id(const HANDLE process_handle)
	{
		return GetProcessId(process_handle);
	}

	inline bool is_explorer(const DWORD process_id)
	{
		const auto process_name = get_process_image_path(process_id);

		return process_name.find(L"explorer32.exe") != std::wstring::npos ||
			process_name.find(L"explorer64.exe") != std::wstring::npos;
	}
} // namespace dr_semu::process::helpers
