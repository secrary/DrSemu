#pragma once

#include "includes.h"

namespace dr_semu::system::handlers
{
	inline bool NtRaiseHardError_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtRaiseHardError(
		//		_In_ NTSTATUS ErrorStatus,
		//		_In_ ULONG NumberOfParameters,
		//		_In_ ULONG UnicodeStringParameterMask,
		//		_In_reads_(NumberOfParameters) PULONG_PTR Parameters,
		//		_In_ ULONG ValidResponseOptions,
		//		_Out_ PULONG Response
		//	);

		const auto valid_response_options = ULONG(dr_syscall_get_param(drcontext, 4));

		dr_printf("[NtRaiseHardError]\n");
		dr_printf("options: %d\n", valid_response_options);
		dr_messagebox("NtRaiseHardError");

		return SYSCALL_CONTINUE;
	}

	inline bool NtUserSystemParametersInfo_handler(void* drcontext)
	{
		//BOOL
		//	APIENTRY
		//	NtUserSystemParametersInfo(
		//		UINT uiAction,
		//		UINT uiParam,
		//		PVOID pvParam,
		//		UINT fWinIni)

		const auto ui_action = UINT(dr_syscall_get_param(drcontext, 0));
		const auto ui_param = UINT(dr_syscall_get_param(drcontext, 1));
		const auto pv_param = PVOID(dr_syscall_get_param(drcontext, 2));
		const auto f_win_ini = UINT(dr_syscall_get_param(drcontext, 3));

		// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa
		// if trying to change a wallpaper
		if (ui_action == SPI_SETDESKWALLPAPER)
		{
			if (pv_param != nullptr)
			{
				const auto wallpaper_path_unicode = static_cast<PUNICODE_STRING>(pv_param);
				std::wstring wallpaper_path{};

				const auto is_valid = utils::unicode_string_to_wstring(wallpaper_path_unicode, wallpaper_path);
				dr_printf("set wallpaper: %ls\n", wallpaper_path.c_str());

				auto is_success = false;

				if (fs::exists(wallpaper_path))
				{
					// TODO(GREEN_MACHINE): add via registry (vReg)
				}

				json set_wallpaper;
				const std::string wallpaper_path_ascii(wallpaper_path.begin(), wallpaper_path.end());
				set_wallpaper["NtUserSystemParametersInfo"]["before"] = {
					{"action", "SPI_SETDESKWALLPAPER"},
					{"path", wallpaper_path_ascii.c_str()},
				};
				set_wallpaper["NtQuerySystemInformation"]["success"] = is_success;

				shared_variables::json_concurrent_vector.push_back(set_wallpaper);
				dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
				return SYSCALL_SKIP;
			}
		}

		// allow get_ actions*
		if (ui_action == SPI_GETDESKWALLPAPER)
		{
			//Retrieves the full path of the bitmap file for the desktop wallpaper.The pvParam parameter must point to a buffer to receive the null - terminated path string.Set the uiParam parameter to the size, in characters, of the pvParam buffer.The returned string will not exceed MAX_PATH characters.If there is no desktop wallpaper, the returned string is empty
		}


		return SYSCALL_CONTINUE;
	}

	inline bool NtLoadDriver_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtLoadDriver(
		//		_In_ PUNICODE_STRING DriverServiceName
		//	);

		// "Pointer to a counted Unicode string that specifies a path to the driver's registry key, \Registry\Machine\System\CurrentControlSet\Services\<DriverName>, where <DriverName> is the name of the driver."
		const auto DriverServiceName = PUNICODE_STRING(dr_syscall_get_param(drcontext, 0));
		std::wstring driver_path{};
		if (utils::unicode_string_to_wstring(DriverServiceName, driver_path))
		{
			// trace call
			std::string reg_path_ascii(driver_path.begin(), driver_path.end());
			json load_driver;
			load_driver["NtLoadDriver"]["before"] = {
				{"reg_path", reg_path_ascii.c_str()},
			};
			load_driver["NtLoadDriver"]["success"] = false;
			shared_variables::json_concurrent_vector.push_back(load_driver);
		}

		dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
		return SYSCALL_SKIP;
	}

	inline bool NtQuerySystemInformation_handler(void* drcontext) // TODO(x): ex
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQuerySystemInformation(
		//		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		//		_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
		//		_In_ ULONG SystemInformationLength,
		//		_Out_opt_ PULONG ReturnLength
		//	);

		const auto information_class = SYSTEM_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 0));
		// SystemInformationClass
		const auto ptr_out_opt_system_information = PVOID(dr_syscall_get_param(drcontext, 1)); // SystemInformation
		const auto information_length = ULONG(dr_syscall_get_param(drcontext, 2)); // SystemInformationLength
		const auto ptr_out_opt_length = PULONG(dr_syscall_get_param(drcontext, 3)); // ReturnLength

		const auto return_status = NtQuerySystemInformation(information_class, ptr_out_opt_system_information,
			information_length, ptr_out_opt_length);
		const auto is_success = NT_SUCCESS(return_status) ? true : false;

		/// trace 
		std::string information_class_trace = "UNKNOWN";
		if (information_class == SystemProcessInformation)
		{
			information_class_trace = "SystemProcessInformation";
		}
		json query_system_info;
		query_system_info["NtQuerySystemInformation"]["before"] = {
			{"information_class", information_class_trace.c_str()},
		};
		query_system_info["NtQuerySystemInformation"]["success"] = is_success;

		/// SystemProcessInformation 
		// hide Dr.Semu related processes (dr_semu::shared_variables::semu_process_names)
		if (is_success && information_class == SystemProcessInformation && ptr_out_opt_system_information != nullptr)
		{
			auto ptr_system_info_prev = static_cast<PSYSTEM_PROCESS_INFORMATION>(ptr_out_opt_system_information);
			auto ptr_system_info_current = PSYSTEM_PROCESS_INFORMATION(
				reinterpret_cast<PBYTE>(ptr_system_info_prev) + ptr_system_info_prev->NextEntryOffset);

			while (ptr_system_info_prev->NextEntryOffset != 0)
			{
				// ptr_system_info_current->ImageName.Buffer ==> process name
				std::wstring process_name{};
				const auto is_valid = utils::unicode_string_to_wstring(&ptr_system_info_current->ImageName,
					process_name);
				if (is_valid)
				{
					// unlink Dr.Semu related process names
					if (shared_variables::semu_process_names.contains(process_name))
					{
						if (ptr_system_info_current->NextEntryOffset == 0)
						{
							ptr_system_info_prev->NextEntryOffset = 0;
						}
						else
						{
							ptr_system_info_prev->NextEntryOffset += ptr_system_info_current->NextEntryOffset;
						}
						ptr_system_info_current = ptr_system_info_prev;
					}
				}
				ptr_system_info_prev = ptr_system_info_current;
				ptr_system_info_current = PSYSTEM_PROCESS_INFORMATION(
					reinterpret_cast<PBYTE>(ptr_system_info_prev) + ptr_system_info_current->NextEntryOffset);
			}
		}

		shared_variables::json_concurrent_vector.push_back(query_system_info);
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}
} // namespace dr_semu::system::handlers
