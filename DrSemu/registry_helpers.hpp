#pragma once

#include "utils.hpp"

namespace dr_semu::registry::helpers
{
	inline std::wstring get_wstring_dos_name_from_object_attributes_reg(const POBJECT_ATTRIBUTES ptr_object_attributes)
	{
		std::wstring object_name_string{};
		auto result = utils::unicode_string_to_wstring(ptr_object_attributes->ObjectName, object_name_string);

		if (ptr_object_attributes->RootDirectory != nullptr)
		{
			DWORD size{};
			auto status = NtQueryKey(ptr_object_attributes->RootDirectory, KeyNameInformation, nullptr, 0, &size);
			if (status == STATUS_BUFFER_TOO_SMALL)
			{
				size += sizeof(WCHAR);
				const auto key_name_information = reinterpret_cast<KEY_NAME_INFORMATION*>(new byte[size]);
				memset(key_name_information, 0, size);

				if (key_name_information != nullptr)
				{
					status = NtQueryKey(ptr_object_attributes->RootDirectory, KeyNameInformation, key_name_information,
					                    size, &size);
					if (status == STATUS_SUCCESS)
					{
						std::wstring key_path{
							key_name_information->Name,
							key_name_information->Name + (key_name_information->NameLength / sizeof(wchar_t))
						};
						delete[] key_name_information;

						//dr_printf("h: %ls\n", key_path.c_str());
						//dr_messagebox("x");
						if (object_name_string.empty())
						{
							return key_path;
						}

						key_path += L'\\';
						key_path += object_name_string;

						return key_path;
					}
				}
			}

			return {}; // failed
		}

		return object_name_string;
	}

	inline bool open_handle_from_virtual_reg(const std::wstring& virtual_handle_path, const DWORD desired_access,
	                                         HKEY& virtual_reg_handle, bool& is_virtual_handle)
	{
		if (utils::find_case_insensitive(virtual_handle_path, LR"(\REGISTRY\MACHINE\)") ||
			utils::find_case_insensitive(virtual_handle_path, LR"(\REGISTRY\USER\)")
			)
		{
			is_virtual_handle = false;
			//virtual_reg_handle = virtual_handle_path == LR"(\REGISTRY\MACHINE\)" ? HKEY_LOCAL_MACHINE : HKEY_USERS;
			return true;
		}
		
		const auto machine_pos = utils::find_case_insensitive(virtual_handle_path, LR"(\REGISTRY\MACHINE\)");
		const auto user_pos = utils::find_case_insensitive(virtual_handle_path, LR"(\REGISTRY\USER\)");
		if (machine_pos != 0 && user_pos != 0)
		{
			// a handle should start with \Machine or \User
			dr_printf("invalid reg handle path: %ls\n", virtual_handle_path.data());
			dr_messagebox("invalid_handle_path");

			return false;
		}

		if (machine_pos == 0)
		{
			const auto virtual_machine_path = virtual_handle_path.substr(
				wcslen(LR"(\REGISTRY\MACHINE\)"), virtual_handle_path.length());
			dr_printf("u: %ls\n", virtual_machine_path.c_str());
			const auto status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, virtual_machine_path.c_str(), 0, desired_access,
			                           &virtual_reg_handle);
			if (status != ERROR_SUCCESS)
			{
				dr_printf("HKEY_LOCAL_MACHINE. subkey: %ls\nstatus: 0x%x last_err: 0x%x\n",
				          virtual_machine_path.c_str(), status, GetLastError());
				return false;
			}
		}
		else if (user_pos == 0)
		{
			const auto virtual_user_path = virtual_handle_path.substr(wcslen(LR"(\REGISTRY\USER\)"),
			                                                          virtual_handle_path.length());
	
			const auto status = RegOpenKeyEx(HKEY_USERS, virtual_user_path.c_str(), 0, desired_access, &virtual_reg_handle);
			if (status != ERROR_SUCCESS)
			{
				dr_printf("HKEY_USERS. subkey: %ls\nstatus: 0x%x last_err: 0x%x\n", virtual_user_path.c_str(), status,
				          GetLastError());
				return false;
			}
		}

		return true;
	}

	inline std::wstring get_path_from_handle_reg(const HANDLE handle, bool& is_deleted)
	{
		is_deleted = false;
		DWORD size{};
		auto status = NtQueryKey(handle, KeyNameInformation, nullptr, 0, &size);
		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			size += sizeof(WCHAR);
			const auto key_name_information = reinterpret_cast<KEY_NAME_INFORMATION*>(new byte[size]);
			memset(key_name_information, 0, size);

			if (key_name_information != nullptr)
			{
				status = NtQueryKey(handle, KeyNameInformation, key_name_information,
				                    size, &size);

				if (status == STATUS_SUCCESS)
				{
					std::wstring return_string = {
						key_name_information->Name,
						key_name_information->Name + (key_name_information->NameLength / sizeof(wchar_t))
					};
					delete[] key_name_information;

					return return_string;
				}

				if (status == STATUS_KEY_DELETED)
				{
					is_deleted = true;
					return {};
				}

				dr_printf("NtQuery(KeyName) failed: 0x%lx\n", status);
			}
		}

		return {};
	}

	inline std::wstring original_to_virtual_reg(std::wstring original_reg_path, bool& is_root, const bool revert = false)
	{
		// \REGISTRY\USER\S-1-5-21-xxxx-1001
		// \Registry\...
		// \REGISTRY\MACHINE\Software\xxxx => \REGISTRY\MACHINE\dr_semu_x!Software\xxxx
		//

		/*
		 * ISSUE: in a virtual Registry there is no CurrentConstrolSet key
		 * SOLUTION: redirect to ControlSetXXX
		 */
		// TODO (lasha): redirect to ACTIVE control set, not always 001
		const std::wstring control_set_string = L"\\CurrentControlSet";
		const auto control_set_location = utils::find_case_insensitive(original_reg_path, control_set_string);
		if (control_set_location != std::wstring::npos)
		{
			// virtual_reg_path.replace(loc, file_reg.first.length(), file_reg.second);
			original_reg_path.replace(control_set_location, control_set_string.length(), L"\\ControlSet001");
		}

		is_root = false;
		if (!utils::starts_with_case_insensitive(original_reg_path, LR"(\REGISTRY\MACHINE)") &&
			!utils::starts_with_case_insensitive(original_reg_path, LR"(\REGISTRY\USER)"))
		{
			return original_reg_path;
		}

		//dr_printf("o: %ls\n", original_reg_path.c_str());
		
		auto virtual_reg_path{original_reg_path};

		if (!revert)
		{
			const auto hklm_string = LR"(\REGISTRY\MACHINE\)";
			const auto user_string = LR"(\REGISTRY\USER\)";
			if (utils::starts_with_case_insensitive(original_reg_path, hklm_string))
			{
				const auto end_part = virtual_reg_path.substr(wcslen(hklm_string), virtual_reg_path.length());
				virtual_reg_path = hklm_string + shared_variables::current_vm_name + L"!" + end_part;
			}
			else if (utils::starts_with_case_insensitive(original_reg_path, user_string))
			{
				const auto end_part = virtual_reg_path.substr(wcslen(user_string), virtual_reg_path.length());
				virtual_reg_path = user_string + shared_variables::current_vm_name + L"!" + end_part;
			}
			else
			{
				if (utils::equals_case_insensitive(original_reg_path, LR"(\REGISTRY\MACHINE)") ||
					utils::equals_case_insensitive(original_reg_path, LR"(\REGISTRY\USER)")
					)
				{
					is_root = true;
					return original_reg_path;
				}
				//dr_printf("[Dr.Semu] Unknown Registry path: %ls\n", original_reg_path.c_str());
			}
		}
		else
		{
			const auto dr_semu_location = utils::find_case_insensitive(original_reg_path, L"dr_semu_");
			const auto dr_semu_end = utils::find_case_insensitive(original_reg_path, L"!");
			if (dr_semu_location == std::wstring::npos ||
				dr_semu_end == std::wstring::npos
				)
			{
				return original_reg_path;
			}

			virtual_reg_path.erase(dr_semu_location, dr_semu_end - dr_semu_location + 1);

			//dr_printf("relocated: %ls\n", virtual_reg_path.c_str());
			//dr_messagebox("dd");
		}


		
		//const auto virtual_local_machine = virtual_reg_root + LR"(\HKEY_LOCAL_MACHINE)";
		//const auto virtual_users = virtual_reg_root + LR"(\HKEY_USERS)";
		//std::unordered_map<std::wstring, std::wstring> file_reg_map
		//{
		//	{LR"(\REGISTRY\USER)", virtual_users},
		//	{LR"(\REGISTRY\MACHINE)", virtual_local_machine}
		//};


		//if (!revert)
		//{
		//	for (const auto& file_reg : file_reg_map)
		//	{
		//		const auto loc = utils::find_case_insensitive(virtual_reg_path, file_reg.first);
		//		if (loc == 0)
		//		{
		//			virtual_reg_path.replace(loc, file_reg.first.length(), file_reg.second);
		//			break;
		//		}
		//	}
		//}
		//else
		//{
		//	for (const auto& file_reg : file_reg_map)
		//	{
		//		const auto loc = utils::find_case_insensitive(virtual_reg_path, file_reg.second);
		//		if (loc == 0)
		//		{
		//			virtual_reg_path.replace(loc, file_reg.second.length(), file_reg.first);
		//			break;
		//		}
		//	}
		//}

		//dr_printf("rel: %ls\n", virtual_reg_path.c_str());
		return virtual_reg_path;
	}

	inline std::wstring get_path_from_object_attributes(POBJECT_ATTRIBUTES const ptr_object_attributes)
	{
		if (ptr_object_attributes->RootDirectory != nullptr)
		{
			auto is_deleted = false;
			const auto path = get_path_from_handle_reg(ptr_object_attributes->RootDirectory, is_deleted);
			if (is_deleted)
			{
				return {};
			}
			return path;
		}

		return {};
	}

	inline std::wstring get_dos_wstring_name_from_handle_reg(HANDLE handle)
	{
		if (handle == nullptr)
		{
			return {};
		}
		std::wstring return_string{};
		// check if its key_handle
		DWORD size = 0;
		auto result = NtQueryKey(handle, KeyNameInformation, nullptr, 0, &size);
		if (result == STATUS_BUFFER_TOO_SMALL) // handle type is key
		{
			if (0 == size)
			{
				return {};
			}
			size += sizeof(WCHAR);
			const auto key_name_information = reinterpret_cast<KEY_NAME_INFORMATION*>(new(std::nothrow) wchar_t[size /
				sizeof(wchar_t)]{});
			if (key_name_information != nullptr)
			{
				result = NtQueryKey(handle, KeyNameInformation, key_name_information,
				                    size, &size);
				if (result == STATUS_SUCCESS)
				{
					// VOLUME_NAME_DOS: \\?\C:\\x..
					const auto return_key_path = dos_prefix; // \REGISTRY\xxx => \\?\REG...
					const std::wstring key_path{
						key_name_information->Name,
						key_name_information->Name + (key_name_information->NameLength / sizeof(WCHAR))
					};

					delete[] key_name_information;

					return_string = return_key_path + key_path;
				}
				else
				{
					dr_printf("[NtQueryKey] failed - handle: 0x%x line: %d\n", handle, __LINE__);
					delete[] key_name_information;

					return {};
				}
			}
		}

		// handle is a file handle
		if (result == STATUS_OBJECT_TYPE_MISMATCH)
		{
			auto number_of_wchar = GetFinalPathNameByHandle(handle, nullptr, 0, VOLUME_NAME_DOS);
			if (number_of_wchar != 0U)
			{
				// If the function fails because lpszFilePath is too small to hold the string plus the terminating null character, the return value is the required buffer size, in TCHARs. 
				// This value includes the size of the terminating null character.
				std::shared_ptr<wchar_t> dos_current_directory{new wchar_t[number_of_wchar]};
				memset(dos_current_directory.get(), 0, number_of_wchar * sizeof(wchar_t));

				number_of_wchar = GetFinalPathNameByHandle(handle, dos_current_directory.get(), number_of_wchar,
				                                           VOLUME_NAME_DOS);

				if (number_of_wchar != 0U)
				{
					const std::wstring key_path(dos_current_directory.get(), wcslen(dos_current_directory.get()));
					return_string = key_path;
				}
			}
		}
		//dr_printf("dos_: %ls\n", return_string.c_str());
		//dr_messagebox("sdas");
		// return DOS path
		return return_string;
	}

	// https://docs.microsoft.com/en-us/windows/desktop/WinProg64/shared-registry-keys
	inline std::wstring redirect_registry_full_path_wow64_reg(const std::wstring& registry_path)
	{
		// \Registry\machine\..

		const auto original_path_upper = utils::to_upper_string(registry_path);
		const auto& original_normal = registry_path;

		auto redirected_path = registry_path;
		const std::wstring reg_software = LR"(\SOFTWARE)";
		const std::wstring reg_syswow64 = LR"(\WOW6432NODE)";

		if (original_path_upper.find(reg_software + reg_syswow64) != std::wstring::npos ||
			original_path_upper.find(LR"(\SOFTWARE\CLASSES\WOW6432NODE)") != std::wstring::npos)
		{
			return original_normal;
		}

		const auto local_machine = std::wstring{ LR"(\REGISTRY\MACHINE\)" };
		const auto is_local_machine = original_path_upper.find(local_machine) != std::wstring::npos;

		if (is_local_machine) // beginning with HKEY_LOCAL_MACHINE
		{
			// SOFTWARE is redirected
			const auto replace_location = original_path_upper.find(reg_software);
			if (replace_location != std::wstring::npos)
			{
				redirected_path.replace(replace_location, reg_software.length(), reg_software + reg_syswow64);
			}

			// SOFTWARE\Classes are SHARED, but some keys are redirected
			if (original_path_upper.find(LR"(\SOFTWARE\CLASSES)") != std::wstring::npos) // shared
			{
				// redirected keys under "CLASSES"
				if (original_path_upper.find(LR"(\SOFTWARE\CLASSES\CLSID)") == std::wstring::npos &&
					original_path_upper.find(LR"(\SOFTWARE\CLASSES\DIRECTSHOW)") == std::wstring::npos &&
					original_path_upper.find(LR"(\SOFTWARE\CLASSES\INTERFACE)") == std::wstring::npos &&
					original_path_upper.find(LR"(\SOFTWARE\CLASSES\MEDIA TYPE)") == std::wstring::npos &&
					original_path_upper.find(LR"(\SOFTWARE\CLASSES\MEDIAFOUNDATION)") == std::wstring::npos
				)
				{
					// SHARED
					redirected_path = original_normal;
				}
			}
				// SOFTWARE\Clients, ** Microsoft**\COM3, ... are SHARED
			else if (
				original_path_upper.find(LR"(\SOFTWARE\CLIENTS)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\COM3)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\CRYPTOGRAPHY\CALAIS\CURRENT)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\CRYPTOGRAPHY\CALAIS\READERS)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\CRYPTOGRAPHY\SERVICES)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\CTF\SYSTEMSHARED)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\CTF\TIP)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\DFS)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\DRIVER SIGNING)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\ENTERPRISECERTIFICATES)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\EVENTSYSTEM)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\MSMQ)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\NON-DRIVER SIGNING)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\NOTEPAD\DEFAULTFONTS)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\OLE)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\RAS)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\RPC)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\SOFTWARE\MICROSOFT\SHARED TOOLS\MSINFO)") != std::
				wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\SYSTEMCERTIFICATES)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\TERMSERVLICENSING)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\TRANSACTION SERVER)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\CONTROL PANEL\CURSORS\SCHEMES)")
				!=
				std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\AUTOPLAYHANDLERS)") !=
				std::
				wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\DRIVEICONS)") != std::
				wstring
				::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\KINDMAP)") != std::
				wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\GROUP POLICY)") != std::wstring
				::npos
				||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\PREVIEWHANDLERS)") != std::
				wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\SETUP)") != std::wstring::npos
				||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\TELEPHONY\LOCATIONS)") != std::
				wstring
				::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\CONSOLE)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\FONTDPI)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\FONTLINK)") != std::wstring::
				npos
				||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\FONTMAPPER)") != std::wstring
				::npos
				||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\FONTS)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\FONTSUBSTITUTES)") != std::
				wstring
				::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\GRE_INITIALIZE)") != std::
				wstring::
				npos ||
				original_path_upper.find(
					LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS)") !=
				std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\LANGUAGEPACK)") != std::
				wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\NETWORKCARDS)") != std::
				wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\PERFLIB)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\PORTS)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\PRINT)") != std::wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\PROFILELIST)") != std::
				wstring::
				npos ||
				original_path_upper.find(LR"(\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\TIME ZONES)") != std::wstring
				::npos
				||
				original_path_upper.find(LR"(\SOFTWARE\POLICIES)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\REGISTEREDAPPLICATIONS)") != std::wstring::npos
			)
			{
				redirected_path = original_normal;
			}
		}
		else // beginning with HKEY_USERS
		{
			// SOFTWARE\Classes are SHARED, but some keys are redirected
			if (original_path_upper.find(LR"(\SOFTWARE\CLASSES\CLSID)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\CLASSES\DIRECTSHOW)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\CLASSES\INTERFACE)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\CLASSES\MEDIA TYPE)") != std::wstring::npos ||
				original_path_upper.find(LR"(\SOFTWARE\CLASSES\MEDIAFOUNDATION)") != std::wstring::npos
			)
			{
				const auto replace_location = original_path_upper.find(reg_software);
				if (replace_location != std::wstring::npos)
				{
					redirected_path.replace(replace_location, reg_software.length(), reg_software + reg_syswow64);
				}
			}
		}

		// HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Classes is linked to HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node
		const std::wstring wow64_classes = LR"(\SOFTWARE\WOW6432NODE\CLASSES)";

		const auto loc = utils::find_case_insensitive(redirected_path, wow64_classes);
		if (loc != std::wstring::npos)
		{
			redirected_path.replace(loc, wow64_classes.length(), LR"(\SOFTWARE\CLASSES\WOW6432NODE)");
		}

		return redirected_path;
	}
	
	// extract type and registry data from a file
	_Success_(return)
	inline bool read_data_and_type_from_file(const std::wstring& file_path, const size_t file_size,
	                                         __out const PBYTE data, __out BYTE& type)
	{
		const auto content_size = file_size - sizeof(BYTE);
		const std::shared_ptr<BYTE> full_content{new BYTE[file_size]};
		memset(full_content.get(), 0, file_size);

		const std::string file_path_ascii{file_path.begin(), file_path.end()};
		const auto dr_file_handle = dr_open_file(file_path_ascii.c_str(), DR_FILE_READ);

		if (INVALID_FILE == dr_file_handle)
		{
			dr_printf("[dr_open_file] failed [KeyValueFullInformation]: %s\n",
			          file_path_ascii.c_str());
			return false;
		}

		const size_t read_size = dr_read_file(dr_file_handle,
		                                      full_content.get(),
		                                      file_size);

		dr_close_file(dr_file_handle);
		if (read_size != file_size)
		{
			dr_printf("[dr_read_file] (reg) failed: %s\nfile_size %d read_size: %d\n", file_path_ascii.c_str(),
			          file_size, read_size);
			return false;
		}

		type = full_content.get()[0];

		memcpy_s(data, content_size, full_content.get() + sizeof(BYTE), content_size);

		return true;
	}

	_Success_(return)

	inline bool get_value_type_from_reg_file(const std::wstring& file_path, __out BYTE& reg_type)
	{
		const std::string file_path_ascii{file_path.begin(), file_path.end()};
		const auto file_handle = dr_open_file(file_path_ascii.data(), DR_FILE_READ);

		if (file_handle == INVALID_FILE)
		{
			return false;
		}
		uint64 data_size{};
		if (!dr_file_size(file_handle, &data_size))
		{
			dr_close_file(file_handle);
			return false;
		}

		// since 1st byte is for reg type, the size always should be >= 1
		if (data_size >= 1)
		{
			const auto read_size = dr_read_file(file_handle, &reg_type, sizeof(BYTE));
			if (read_size != sizeof(BYTE))
			{
				dr_close_file(file_handle);
				return false;
			}
			dr_close_file(file_handle);
			return true;
		}
		dr_close_file(file_handle);
		return false;
	}

	// if handle is not from virtual_reg => return virtual handle
	inline bool get_virtual_handle(const HKEY handle, HKEY& virtual_handle, bool& is_root)
	{
		virtual_handle = nullptr;
		is_root = false;
		
		if (!utils::is_valid_handle(handle))
		{
			dr_printf("[get_virtual_handle] invalid reg handle: 0x%x\n", handle);
			return false;
		}

		auto is_deleted = false;
		const auto handle_path = get_path_from_handle_reg(handle, is_deleted);
		if (is_deleted)
		{
			dr_printf("Deleted reg key: 0x%lx\n", handle);
			return false;
		}

		if (!handle_path.empty() && handle_path.find(shared_variables::current_vm_name) == std::wstring::npos)
		{
			const auto virtual_handle_path = original_to_virtual_reg(handle_path, is_root);
			if (is_root)
			{
				return false;
			}

			const auto desired_access = utils::get_handle_granted_access(handle);

			auto is_virtual_handle = false;
			const auto is_valid = open_handle_from_virtual_reg(virtual_handle_path, desired_access, virtual_handle, is_virtual_handle);
			if (is_valid && !is_virtual_handle)
			{
				// it's root handle
				return false;
			}
			if (!is_valid)
			{
				dr_printf("[get_virtual_handle] Open virtual_reg handle failed.\npath: %ls\n",
				          virtual_handle_path.c_str());
				dr_messagebox("it should not failed");
				return false;
			}

			return true;
		}

		if (handle_path.empty())
		{
			dr_printf("[get_virtual_handle] Failed get a reg path.\nhandle: 0x%lx\n", handle);
			//dr_messagebox("empty string. check it");
		}

		return false;
	}

	//// use original_to_virtual(..., true)
	//inline std::wstring virtual_to_original_reg(const std::wstring& virtual_path)
	//{
	//	const auto virtual_reg_root = std::wstring{LR"(\REGISTRY\MACHINE\)"} + shared_variables::current_vm_name;
	//	auto original_path = virtual_path;
	//	const auto loc = utils::find_case_insensitive(virtual_path, virtual_reg_root);
	//	// if it's already relocated
	//	if (loc != 0)
	//	{
	//		return original_path;
	//	}

	//	original_path.replace(loc, virtual_reg_root.length(), L"");
	//	return original_path;
	//}

	inline std::wstring get_key_path_trace(const POBJECT_ATTRIBUTES ptr_object_attributes)
	{
		std::wstring object_name_string{};
		auto result = utils::unicode_string_to_wstring(ptr_object_attributes->ObjectName, object_name_string);
		std::wstring handle_path{};
		if (ptr_object_attributes->RootDirectory != nullptr)
		{
			auto is_deleted = false;
			handle_path = get_path_from_handle_reg(ptr_object_attributes->RootDirectory, is_deleted);
			if (is_deleted)
			{
				dr_printf("[get_key_path_trace] reg key is deleted: 0x%lx\n", ptr_object_attributes->RootDirectory);
				return {};
			}
		}

		std::wstring full_key_path{};
		if (!handle_path.empty())
		{
			full_key_path = handle_path + L"\\" + object_name_string;
		}
		else
		{
			full_key_path = object_name_string;
		}
		auto is_root = false;
		const auto original_full_path = original_to_virtual_reg(full_key_path, is_root);

		return original_full_path;
	}

	inline OBJECT_ATTRIBUTES get_virtual_object_attributes_reg(const POBJECT_ATTRIBUTES ptr_object_attributes,
	                                                           const bool cross_access, bool& is_virtual_handle,
	                                                           std::wstring& trace_string, bool& is_deleted)
	{
		std::wstring object_name_string{};
		auto result = utils::unicode_string_to_wstring(ptr_object_attributes->ObjectName, object_name_string);

		HKEY virtual_reg_handle = nullptr;
		is_virtual_handle = false;
		auto is_root = false;
		if (ptr_object_attributes->RootDirectory != nullptr)
		{
			is_virtual_handle = get_virtual_handle(HKEY(ptr_object_attributes->RootDirectory),
			                                       virtual_reg_handle, is_root);
		}

		auto is_root_inside = false;
		object_name_string = original_to_virtual_reg(object_name_string, is_root_inside);

		if (is_root)
		{
			object_name_string = shared_variables::current_vm_name + L"!" + object_name_string;
			//dr_printf("only_name: %ls\nroot: 0x%lx\n", object_name_string.c_str(), ptr_object_attributes->RootDirectory);
			//dr_messagebox("Xxx");
		}
		
		// redirect
		if (!cross_access)
		{
			is_deleted = false;
			auto handle_path = get_path_from_handle_reg(is_virtual_handle
				                                            ? virtual_reg_handle
				                                            : ptr_object_attributes->RootDirectory, is_deleted);
			if (is_deleted)
			{
				trace_string = L"<DELETED_KEY>";
				//dr_printf("[get_virtual_object_attributes_reg] deleted reg key\n");
				return {};
			}

			if (!handle_path.empty())
			{
				handle_path += os_path_separator;
			}
			auto full_path = handle_path + object_name_string;
			full_path = redirect_registry_full_path_wow64_reg(full_path);
			object_name_string = full_path.substr(handle_path.length(), full_path.length());
		}

		const auto unicode_string = new UNICODE_STRING{};
		if (!object_name_string.empty())
		{
			RtlCreateUnicodeString(unicode_string, object_name_string.data());
		}
		else
		{
			RtlCopyUnicodeString(unicode_string, ptr_object_attributes->ObjectName);
		}
		OBJECT_ATTRIBUTES new_object_attributes;
		InitializeObjectAttributes(&new_object_attributes, unicode_string, ptr_object_attributes->Attributes,
		                           is_virtual_handle ? virtual_reg_handle : ptr_object_attributes->RootDirectory,
		                           ptr_object_attributes->SecurityDescriptor);
		new_object_attributes.SecurityQualityOfService = ptr_object_attributes->SecurityQualityOfService;

		// get trace string
		is_deleted = false;
		const auto handle_path = get_path_from_handle_reg(new_object_attributes.RootDirectory, is_deleted);
		std::wstring reg_second_path{};
		utils::unicode_string_to_wstring(ptr_object_attributes->ObjectName, reg_second_path);
		std::wstring full_path{};
		if (!handle_path.empty())
		{
			full_path = handle_path + L"\\" + reg_second_path;
		}
		else
		{
			full_path = reg_second_path;
		}

		trace_string = original_to_virtual_reg(full_path, is_root_inside,  true);


		return new_object_attributes;
	}
} // namespace dr_semu::registry::helpers
