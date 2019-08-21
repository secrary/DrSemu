#pragma once

#include "includes.h"
#include <unordered_set>


namespace dr_semu::filesystem::helpers
{
	// exact match (fast)
	inline std::unordered_set<std::wstring> whitelisted_devices{
		LR"(\Device\CNG)",
		LR"(\Device\KsecDD)", // cryptographic modules
		LR"(\Device\DeviceApi\CMApi)",
		LR"(\Device\ConDrv)",
		LR"(\Device\RasAcd)", // RAS Automatic Connection Driver
		//LR"(\Device\DeviceApi\CMNotify)",
	};

	// enumerate (slower)
	inline std::vector<std::wstring> whitelisted_starts{
		// "supports Windows sockets applications and is contained in the afd.sys file. The afd.sys driver runs in kernel mode and manages the Winsock TCP/IP communications protocol"
		LR"(\Device\Afd)",

		LR"(\Device\NamedPipe\)",
		LR"(\??\PIPE\)",
	};

	// https://blogs.msdn.microsoft.com/jeremykuhne/2016/05/02/dos-to-nt-a-paths-journey/
	// https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html

	inline bool is_handle_file_or_dir(const HANDLE handle)
	{
		DWORD type_info_size{};
		auto status = NtQueryObject(handle, ObjectTypeInformation, nullptr, 0, &type_info_size);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			const auto type_information{new byte[type_info_size]};
			const auto in_size = type_info_size;
			status = NtQueryObject(handle, ObjectTypeInformation, type_information, in_size, &type_info_size);
			if (!NT_SUCCESS(status))
			{
				return false;
			}
			const auto ptr_type_information = reinterpret_cast<POBJECT_TYPE_INFORMATION>(type_information);

			const std::wstring type_name(ptr_type_information->TypeName.Buffer,
			                             wcslen(ptr_type_information->TypeName.Buffer));

			return type_name == L"File";
		}

		return false;
	}

	inline bool is_whitelisted_device_name(const std::wstring& handle_name)
	{
		return whitelisted_devices.find(handle_name) != whitelisted_devices.end();
	}

	// without redir
	inline std::wstring get_full_path(const HANDLE root_handle, const std::wstring& name)
	{
		std::wstring root_path{};
		if (root_handle != nullptr)
		{
			auto is_unnamed = false;
			root_path = utils::get_name_from_handle(root_handle, is_unnamed);
		}

		const auto full_path = root_path.empty() ? name : root_path + (name.empty() ? L"" : L"\\" + name);
		return full_path;
	}

	inline std::wstring get_full_path(const POBJECT_ATTRIBUTES ptr_object_attributes)
	{
		std::wstring name{};
		const auto is_valid = utils::unicode_string_to_wstring(ptr_object_attributes->ObjectName, name);

		return get_full_path(ptr_object_attributes->RootDirectory, name);
	}

	inline std::wstring get_full_path(const HANDLE root_handle, const PUNICODE_STRING unicode_name)
	{
		std::wstring name{};
		const auto is_valid = utils::unicode_string_to_wstring(unicode_name, name);

		return get_full_path(root_handle, name);
	}

	inline std::wstring get_path_from_handle(const HANDLE handle, _Out_ bool& whitelisted, bool get_nt_path = false)
	{
		whitelisted = false;

		if (!utils::is_valid_handle(handle))
		{
			dr_printf("[get_dos_path_from_handle] invalid handle value: 0x%lx\n", handle);
			return nullptr;
		}

		if (!is_handle_file_or_dir(handle))
		{
			dr_printf("get_dos_fs. not file/dir. handle :0x%x\n", handle);
			//dr_messagebox("xxx");
			whitelisted = true;
			return {};
		}

		// I think it's safer to whitelist device names
		// other option is to whitelist everything but \Device\HarddiskVolume (we can miss unsafe device access)
		// much safer to whitelist known safe devices

		// check a device name
		auto is_unnamed = false;
		const auto handle_name = utils::get_name_from_handle(handle, is_unnamed);
		if (is_unnamed)
		{
			whitelisted = true;
			return {};
		}

		if (!networking::config::disable_internet)
		{
			if (utils::find_case_insensitive(handle_name, LR"(\??\Nsi)") == 0)
			{
				whitelisted = true;
				return {};
			}
		}

		if (handle_name.find(LR"(\Device)") == 0)
		{
			if (is_whitelisted_device_name(handle_name))
			{
				whitelisted = true;
				return {};
			}

			for (const auto& device_name : whitelisted_starts)
			{
				if (handle_name.find(device_name) == 0)
				{
					whitelisted = true;
					return {};
				}
			}
		}

		// all handles should be to valid a file/dir
		const auto path_type = get_nt_path ? VOLUME_NAME_NT : VOLUME_NAME_DOS;
		auto number_of_wchar = GetFinalPathNameByHandle(handle, nullptr, 0, path_type);
		if (number_of_wchar != 0U)
		{
			// If the function fails because lpszFilePath is too small to hold the string plus the terminating null character, the return value is the required buffer size, in TCHARs. 
			// This value includes the size of the terminating null character.
			const std::shared_ptr<wchar_t> handle_path{new wchar_t[number_of_wchar]};
			memset(handle_path.get(), 0, number_of_wchar * sizeof(wchar_t));

			number_of_wchar = GetFinalPathNameByHandle(handle, handle_path.get(), number_of_wchar, path_type);

			if (number_of_wchar != 0U)
			{
				const std::wstring dos_file_name{handle_path.get(), number_of_wchar};
				return dos_file_name;
			}
		}
		else
		{
			dr_printf("unknown handle name\nhandle: 0x%x\nname: %ls\n", handle, handle_name.c_str());
			dr_messagebox("check handle name");
		}

		return {};
	}

	inline std::wstring get_real_windows_directory()
	{
		return std::wstring{shared_variables::virtual_filesystem_location.wstring()[0]} + L":\\Windows";
	}

	inline bool redirect_system32_to_syswow64(std::wstring& path)
	{
		const auto lower_string = utils::to_lower_string(path);
		const auto& original_path{lower_string};

		const auto system32 = LR"(windows\system32)";
		const auto last_good = LR"(windows\lastgood\system32)";
		const auto regedit = LR"(windows\regedit.exe)";
		if (const auto system32_loc = lower_string.find(system32); system32_loc != std::wstring::npos)
		{
			path.replace(system32_loc, wcslen(system32), LR"(Windows\SysWOW64)");
		}
		else if (const auto lastgood_loc = lower_string.find(last_good); lastgood_loc != std::wstring::npos)
		{
			path.replace(lastgood_loc, wcslen(last_good), LR"(Windows\lastgood\SysWOW64)");
		}
		else if (const auto regedit_loc = lower_string.find(regedit); regedit_loc != std::wstring::npos)
		{
			path.replace(regedit_loc, wcslen(regedit), LR"(Windows\SysWOW64\regedit.exe)");
		}

		if (
			original_path.find(LR"(windows\system32\catroot)") != std::wstring::npos ||
			original_path.find(LR"(windows\system32\catroot2)") != std::wstring::npos ||
			original_path.find(LR"(windows\system32\driverstore)") != std::wstring::npos ||
			original_path.find(LR"(windows\system32\drivers\etc)") != std::wstring::npos ||
			original_path.find(LR"(windows\system32\logfiles)") != std::wstring::npos ||
			original_path.find(LR"(windows\system32\spool)") != std::wstring::npos
		)
		{
			path = original_path;
		}

		return true;
	}

	inline std::wstring get_redirected_device_path(const std::wstring& harddisk_path)
	{
		// Redirect to main drive, even if it's from different one
		// TODO (lasha): Do we care other drives?
		const std::wstring device_pattern = LR"(\Device\HarddiskVolume)";
		if (utils::find_case_insensitive(harddisk_path, device_pattern) != 0)
		{
			return {};
		}
		if (utils::find_case_insensitive(harddisk_path, shared_variables::v_fs_device_form) == 0)
		{
			return harddisk_path;
		}

		auto device_name_size = device_pattern.length();
		while (harddisk_path[device_name_size++] != L'\\')
		{
		}

		auto redirected_string{harddisk_path};

		redirected_string.replace(0, device_name_size - 1, shared_variables::v_fs_device_form);

		return redirected_string;
	}

	inline bool relocate_path_virtual_fs(const std::wstring& original_path, std::wstring& relocated_path)
	{
		// if it's already relocated
		if (
			utils::find_case_insensitive(
				original_path, shared_variables::virtual_filesystem_location.wstring()) != std::wstring::npos
		)
		{
			relocated_path = original_path;
			return true;
		}

		relocated_path = original_path;
		const auto loc = relocated_path.find(L':');
		if (loc == std::wstring::npos)
		{
			return false;
		}
		// D:\ => C:\path\to\virtual_fs
		relocated_path.replace(loc - 1, 2, shared_variables::virtual_filesystem_location.wstring());


		// NtCurrentTeb64()->TlsSlots[WOW64_TLS_FILESYSREDIR]
		if (dr_is_wow64())
		{
			const auto ptr_teb = NtCurrentTeb();
			const auto is_wow_disabled = *((PBYTE(ptr_teb) + ptr_teb->WowTebOffset) + 0x14C0) != 0U;

			if (!is_wow_disabled)
			{
				if (!redirect_system32_to_syswow64(relocated_path))
				{
					return false;
				}
			}
		}

		return true;
	}

	// UNC - used to access remote file systems
	// UNC is a symbolic link to \Device\Mup
	inline bool is_unc(const std::wstring& path)
	{
		// TODO (lasha): whitelist \??\UNC\localhost\...
		return path.find(LR"(?\UNC\)") != std::wstring::npos || path.find(LR"(\Device\Mup)") != std::wstring::npos;
	}

	inline bool is_path_expected(const std::wstring& path)
	{
		// \??\x:
		return
			path[0] == L'\\' &&
			path[1] == L'?' &&
			path[2] == L'?' &&
			path[3] == L'\\' &&
			// disk number here
			path[5] == L':';
	}

	inline std::wstring normalize_path(std::wstring_view path)
	{
		std::wstring normalized_path(path);

		if (path.find(LR"(\\?\)") != std::wstring::npos
			|| path.find(LR"(\??\)") != std::wstring::npos
			|| path.find(LR"(\\.\)") != std::wstring::npos
		)
		{
			normalized_path = path.substr(4);
		}

		return normalized_path;
	}

	inline std::wstring virtual_to_original_fs(const std::wstring& virtual_path)
	{
		const auto drcontext = dr_get_current_drcontext();
		const auto tid = dr_get_thread_id(drcontext);

		if (utils::find_case_insensitive(virtual_path, LR"(C:\)") != std::wstring::npos &&
			utils::find_case_insensitive(
				virtual_path, shared_variables::virtual_filesystem_location.wstring()) == std::wstring::npos
		)
		{
			dr_printf("[TID: %d] Path should be virtual: %ls\n", tid, virtual_path.c_str());
			dr_messagebox("investigate path");
			return {};
		}

		auto original_path = virtual_path;
		const auto loc = utils::find_case_insensitive(
			virtual_path,
			shared_variables::virtual_filesystem_location.wstring());

		// if it's already relocated
		if (loc == std::wstring::npos)
		{
			return original_path;
		}
		// C:\Temp\dir => C:
		original_path.replace(
			loc + 2,
			shared_variables::virtual_filesystem_location.wstring().length() - 2, L"");
		return original_path;
	}

	inline std::wstring get_virtual_system_root_nt_path(const std::wstring& system_root_path)
	{
		const std::wstring system_root_name{LR"(\SystemRoot)"};
		if (utils::find_case_insensitive(system_root_path, system_root_name) != 0)
		{
			return {};
		}
		std::wstring virtual_system_root_nt = LR"(\??\)";
		const auto windows_directory = get_real_windows_directory();
		std::wstring virtual_win_dir{};

		relocate_path_virtual_fs(windows_directory, virtual_win_dir);
		virtual_system_root_nt += virtual_win_dir;
		auto virtual_system_root_full_path{system_root_path};
		virtual_system_root_full_path.replace(0, system_root_name.length(), virtual_system_root_nt);

		return virtual_system_root_full_path;
	}

	inline std::wstring syswow64_to_system32(const std::wstring& file_path)
	{
		auto return_path{file_path};
		const std::wstring syswow = LR"(\syswow64\)";
		const auto loc = utils::find_case_insensitive(file_path, syswow);
		if (loc == std::wstring::npos)
		{
			return return_path;
		}

		return return_path.replace(loc, syswow.length(), LR"(\system32\)");
	}

	// relocate path to virtual_fs and redirect to wow64 if necessary
	// if ret/false => deny a call
	inline bool original_path_to_virtual_fs(const std::wstring& original_path, std::wstring& virtual_path)
	{
		// Assume that original_path is NT path
		// virtual_path also NT path

		// if it's already relocated
		if (
			utils::find_case_insensitive(
				original_path, shared_variables::virtual_filesystem_location.wstring()) != std::wstring::npos
		)
		{
			virtual_path = original_path;
			return true;
		}

		// UNC is forbiden
		if (is_unc(original_path))
		{
			return false;
		}

		// TODO (x): \??\STORAGE#Volume#

		// is console input/output? - \??\CONIN$ and \??\CONOUT$
		// https://support.microsoft.com/en-us/help/90088/info-createfile-using-conout-or-conin
		if (
			original_path.find(LR"(\??\CONIN$)") == 0 ||
			original_path.find(LR"(\??\CONOUT$)") == 0
		)
		{
			virtual_path = original_path;
			return true;
		}


		// \SystemRoot\WinSxS\file.txt
		// \??\x:\[virtual_fs]\Windows\WinSxS\file.txt
		const std::wstring system_root_name{LR"(\SystemRoot)"};
		if (utils::find_case_insensitive(original_path, system_root_name) == 0)
		{
			const auto virtual_system_path = get_virtual_system_root_nt_path(original_path);

			if (virtual_system_path.empty())
			{
				dr_printf("SYSROOT err: %ls\n", virtual_path.c_str());
				dr_messagebox("SystemRoot reloc");
				return false;
			}

			virtual_path = virtual_system_path;
			return true;
		}

		const auto redirected_path = get_redirected_device_path(original_path);
		if (!redirected_path.empty())
		{
			virtual_path = redirected_path;
			return true;
		}

		if (!networking::config::disable_internet)
		{
			if (utils::find_case_insensitive(original_path, LR"(\??\Nsi)") == 0)
			{
				virtual_path = original_path;
				return true;
			}
		}

		// whitelisted devices: \Device\CNG, etc.
		if (is_whitelisted_device_name(original_path))
		{
			virtual_path = original_path;
			return true;
		}
		for (const auto& device_name : whitelisted_starts)
		{
			if (original_path.find(device_name) == 0)
			{
				virtual_path = original_path;
				return true;
			}
		}

		if (original_path.find(LR"(\??\::)") == 0) // start
		{
			// TODO (lasha): how to handle?
			return false;
		}

		// if path is not NT ("\??\") (start)
		if (original_path.find(nt_file_prefix) != 0)
		{
			//dr_printf("NOT NT path: %ls\n", original_path.c_str());
			//dr_messagebox("not NT path");
			return false;
		}
		// unusual path
		if (!is_path_expected(original_path))
		{
			//dr_printf("unusual path: %ls\n", original_path.c_str());
			//dr_messagebox("unusual path");
			return false;
		}

		// expected NT path: \??\x:\dir
		// \??\C:\dir => \??\C:\path_to_virtual_fs\dir
		std::wstring relocated_path{};
		const auto result = relocate_path_virtual_fs(original_path, relocated_path);
		if (result)
		{
			virtual_path = relocated_path;
			return true;
		}

		dr_printf("[original_path_to_virtual_fs] unhandled path: %ls\n", original_path.c_str());
		dr_messagebox("check path");
		return false;
	}


	// checks if a handle path is under virtual_fs, if not returns new handle from virtual_fs
	// return: true if virtual_file_handle points to a NEW file from virtual_fs

	// if ret_val is false use the original handle (already from vFS or whitelisted)
	inline bool get_virtual_handle_fs(const HANDLE handle, HANDLE& virtual_file_handle, bool& access_denied)
	{
		access_denied = false;

		// if handle is ConDrv return true and set virt_handle = handle
		if (!utils::is_valid_handle(handle))
		{
			return false;
		}

		auto whitelisted = false;
		auto dos_path = get_path_from_handle(handle, whitelisted);
		if (dos_path.empty())
		{
			if (!whitelisted)
			{
				dr_printf("[get_dos_path_from_handle] failed. handle: 0x%x\n", handle);
				access_denied = true;
				return false;
			}
			// whitelisted, use old handle
			return false;
		}
		if (utils::find_case_insensitive(dos_path, shared_variables::virtual_filesystem_location.wstring()) != std::
			wstring::npos)
		{
			return false;
		}
		UNICODE_STRING nt_path_unicode{};
		RtlDosPathNameToNtPathName_U(dos_path.data(), &nt_path_unicode, nullptr, nullptr);
		std::wstring nt_path{};
		const auto is_nt_path = utils::unicode_string_to_wstring(&nt_path_unicode, nt_path);
		if (!is_nt_path)
		{
			return false;
		}

		std::wstring virtual_path{};
		if (!original_path_to_virtual_fs(nt_path, virtual_path))
		{
			access_denied = true;
			return false;
		}

		const auto desired_access = utils::get_handle_granted_access(handle);

		const auto file_attributes_real = GetFileAttributes(nt_path.c_str());
		const auto is_directory_real = (file_attributes_real & FILE_ATTRIBUTE_DIRECTORY) != 0U;
		const auto is_existing_virtual = GetFileAttributes(virtual_path.c_str()) != INVALID_FILE_ATTRIBUTES;

		if (is_directory_real)
		{
			if (!is_existing_virtual)
			{
				CreateDirectory(virtual_path.c_str(), nullptr);
			}
			virtual_file_handle = CreateFile(virtual_path.c_str(),
			                                 desired_access,
			                                 FILE_SHARE_READ,
			                                 nullptr,
			                                 OPEN_EXISTING,
			                                 FILE_FLAG_BACKUP_SEMANTICS,
			                                 nullptr);
			if (virtual_file_handle != INVALID_HANDLE_VALUE)
			{
				return true;
			}
			dr_printf("open_dir: %ls failed. err: 0x%x\n", virtual_path.c_str(), GetLastError());
			return false;
		}
		// if it's file
		dr_printf("[missed handle] file: %ls\n", nt_path.c_str());
		dr_messagebox("interesting case, missed handle is a file");
		if (!is_existing_virtual)
		{
			const auto create_handle = CreateFile(virtual_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			                                      OPEN_EXISTING, 0, nullptr);
			if (create_handle != INVALID_HANDLE_VALUE)
			{
				NtClose(create_handle);
			}
		}
		virtual_file_handle = CreateFile(virtual_path.c_str(),
		                                 desired_access,
		                                 0,
		                                 nullptr,
		                                 OPEN_EXISTING,
		                                 0,
		                                 nullptr);
		if (virtual_file_handle != INVALID_HANDLE_VALUE)
		{
			return true;
		}
		dr_printf("open_file: %ls failed. err: 0x%x\n", virtual_path.c_str(), GetLastError());
		return false;
	}

	inline bool redirect_mailslot_string(std::wstring& mailslot_path)
	{
		if (utils::find_case_insensitive(mailslot_path, LR"(\??\mailslot\)") == std::wstring::npos)
		{
			return false;
		}

		const auto loc = utils::find_case_insensitive(mailslot_path, shared_variables::current_vm_name);
		if (loc != std::wstring::npos)
		{
			dr_printf("[redirect_mailslot_string] there should be vm_name in maislot name: %ls\n",
			          mailslot_path.c_str());
			dr_messagebox("vm_name in maislot name");
			return true;
		}

		mailslot_path += shared_variables::current_vm_name;
		return true;
	}

	// ret/ true if object_attributes -> virtual_fs
	// if ret == false => deny a call
	inline bool get_virtual_object_attributes_fs(
		POBJECT_ATTRIBUTES ptr_object_attributes,
		POBJECT_ATTRIBUTES virtual_object_attributes,
		bool& is_virtual_handle,
		bool& is_new_unicode
	)
	{
		is_new_unicode = false;
		if (ptr_object_attributes->RootDirectory != nullptr)
		{
			// if a handle name is empty => allow execution
			// example: CreatePipe(...)
			auto is_unnamed = false;
			const auto handle_path = utils::get_name_from_handle(ptr_object_attributes->RootDirectory, is_unnamed);
			if (is_unnamed)
			{
				is_virtual_handle = false;
				InitializeObjectAttributes(virtual_object_attributes, ptr_object_attributes->ObjectName,
				                           ptr_object_attributes->Attributes, ptr_object_attributes->RootDirectory,
				                           ptr_object_attributes->SecurityDescriptor);
				virtual_object_attributes->SecurityQualityOfService = ptr_object_attributes->SecurityQualityOfService;
				return true;
			}
		}

		std::wstring object_name{};
		HANDLE virtual_file_handle = nullptr;
		if (ptr_object_attributes->ObjectName != nullptr)
		{
			const auto is_valid_string = utils::unicode_string_to_wstring(
				ptr_object_attributes->ObjectName, object_name);
			if (!is_valid_string)
			{
				return false;
			}
		}

		// is it maislot?
		if (redirect_mailslot_string(object_name))
		{
			is_virtual_handle = false;
		}
		else // assume its a file
		{
			is_virtual_handle = false;
			if (ptr_object_attributes->RootDirectory != nullptr)
			{
				if (is_handle_file_or_dir(ptr_object_attributes->RootDirectory))
				{
					bool acccess_denied = false;
					is_virtual_handle =
						get_virtual_handle_fs(ptr_object_attributes->RootDirectory, virtual_file_handle,
						                      acccess_denied);
					if (acccess_denied)
					{
						return false;
					}
				}
			}
			else
			{
				// ObjectName specifies full path
				if (!object_name.empty())
				{
					const auto is_valid = original_path_to_virtual_fs(object_name, object_name);
					if (!is_valid)
					{
						// deny a call
						return false;
					}
				}
			}
		}

		//const auto test_str = helpers::get_full_path(virtual_object_attributes->RootDirectory, object_name);
		//if (
		//	utils::find_case_insensitive(test_str, LR"(C:\)") != std::wstring::npos &&
		//	utils::find_case_insensitive(test_str, shared_variables::virtual_filesystem_location.wstring()) == std::wstring::npos
		//	)
		//{
		//	dr_printf("Failed to get a virtual_path: %ls\n", test_str.c_str());
		//	dr_messagebox("failed to get a virtual path");
		//}

		const auto unicode_string = new UNICODE_STRING{};
		is_new_unicode = true;
		if (!object_name.empty())
		{
			RtlCreateUnicodeString(unicode_string, object_name.data());
		}
		else if ((ptr_object_attributes->ObjectName != nullptr) && ptr_object_attributes->ObjectName->Length != 0U)
		{
			RtlCopyUnicodeString(unicode_string, ptr_object_attributes->ObjectName);
		}
		InitializeObjectAttributes(virtual_object_attributes, unicode_string, ptr_object_attributes->Attributes,
		                           is_virtual_handle ? virtual_file_handle : ptr_object_attributes->RootDirectory,
		                           ptr_object_attributes->SecurityDescriptor);
		virtual_object_attributes->SecurityQualityOfService = ptr_object_attributes->SecurityQualityOfService;

		return true;
	}

	inline std::wstring get_original_full_path(const HANDLE root_handle, const std::wstring& name)
	{
		//const auto drcontext = dr_get_current_drcontext();
		//const auto tid = dr_get_thread_id(drcontext);

		const auto full_path = get_full_path(root_handle, name);

		return virtual_to_original_fs(full_path);
	}

	inline std::wstring get_original_full_path(const HANDLE root_handle, const PUNICODE_STRING unicode_name)
	{
		std::wstring name{};
		const auto is_valid = utils::unicode_string_to_wstring(unicode_name, name);

		return get_original_full_path(root_handle, name);
	}

	inline std::wstring get_original_full_path(const POBJECT_ATTRIBUTES ptr_object_attributes)
	{
		return get_original_full_path(ptr_object_attributes->RootDirectory, ptr_object_attributes->ObjectName);
	}
} // namespace dr_semu::filesystem::helpers
