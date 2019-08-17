#include "delete.hpp"
#include "virtual_reg.h"
//#include "regclone.h"

#include <aclapi.h>
#include <future>
#include "utils.hpp"

namespace registry
{
	SECURITY_ATTRIBUTES virtual_registry::get_full_access_security_attributes() const
	{
		PSID p_everyone_sid = nullptr, p_admin_sid = nullptr;
		PACL p_acl = nullptr;
		EXPLICIT_ACCESS ea[2];
		SID_IDENTIFIER_AUTHORITY sid_auth_world =
			SECURITY_WORLD_SID_AUTHORITY;
		SID_IDENTIFIER_AUTHORITY sid_auth_nt = SECURITY_NT_AUTHORITY;
		
		SECURITY_ATTRIBUTES security_attributes;
		security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		security_attributes.bInheritHandle = FALSE;
		security_attributes.lpSecurityDescriptor = nullptr;

		// Create a well-known SID for the Everyone group.
		if (!AllocateAndInitializeSid(&sid_auth_world, 1,
		                              SECURITY_WORLD_RID,
		                              0, 0, 0, 0, 0, 0, 0,
		                              &p_everyone_sid))
		{
			spdlog::error("AllocateAndInitializeSid Error {}", GetLastError());
			return security_attributes;
		}

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName = static_cast<LPTSTR>(p_everyone_sid);

		// Create a SID for the BUILTIN\Administrators group.
		if (!AllocateAndInitializeSid(&sid_auth_nt, 2,
		                              SECURITY_BUILTIN_DOMAIN_RID,
		                              DOMAIN_ALIAS_RID_ADMINS,
		                              0, 0, 0, 0, 0, 0,
		                              &p_admin_sid))
		{
			spdlog::error("AllocateAndInitializeSid Error {}", GetLastError());
			return security_attributes;
		}

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow the Administrators group full access to
		// the key.
		ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
		ea[1].grfAccessMode = SET_ACCESS;
		ea[1].grfInheritance = NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[1].Trustee.ptstrName = static_cast<LPTSTR>(p_admin_sid);

		// Create a new ACL that contains the new ACEs.
		const auto dw_res = SetEntriesInAcl(2, ea, nullptr, &p_acl);
		if (ERROR_SUCCESS != dw_res)
		{
			spdlog::error("SetEntriesInAcl Error {}", GetLastError());
			return security_attributes;
		}

		// Initialize a security descriptor.  
		const auto p_sd = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR,
		                                                                         SECURITY_DESCRIPTOR_MIN_LENGTH));
		if (nullptr == p_sd)
		{
			spdlog::error("LocalAlloc Error {}", GetLastError());
			return security_attributes;
		}

		if (!InitializeSecurityDescriptor(p_sd,
		                                  SECURITY_DESCRIPTOR_REVISION))
		{
			spdlog::error("InitializeSecurityDescriptor Error {}", GetLastError());
			return security_attributes;
		}

		// Add the ACL to the security descriptor. 
		if (!SetSecurityDescriptorDacl(p_sd,
		                               TRUE, // bDaclPresent flag   
		                               p_acl,
		                               FALSE)) // not a default DACL 
		{
			spdlog::error("SetSecurityDescriptorDacl Error {}", GetLastError());
			return security_attributes;
		}

		security_attributes.lpSecurityDescriptor = p_sd;
		return security_attributes;
	}

	std::vector<std::wstring> enumerate_key_names(const HKEY root_key)
	{
		std::vector<std::wstring> key_names{};
		DWORD number_of_keys = 0;
		auto ret_code = RegQueryInfoKey(
			root_key,
			nullptr,
			nullptr,
			nullptr,
			&number_of_keys,
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr);

		const std::unique_ptr<TCHAR> key_name{ new TCHAR[MAX_PATH] };

		if (number_of_keys)
		{

			for (DWORD i = 0; i < number_of_keys; i++)
			{
				DWORD name_size = MAX_PATH;
				ret_code = RegEnumKeyEx(root_key, i,
					key_name.get(),
					&name_size,
					nullptr,
					nullptr,
					nullptr,
					nullptr);
				if (ret_code == ERROR_SUCCESS)
				{
					key_names.emplace_back(key_name.get());
				}
			}
		}

		return key_names;
	}
	
	bool virtual_registry::save_root_key(const std::wstring_view target_key_name) const
	{
		const auto key_handle = target_key_name == L"HKLM" ? HKEY_LOCAL_MACHINE : HKEY_USERS;
		const auto target_directory = virtual_reg_data_dir_ + L"\\" + target_key_name.data() + L"_" + vm_prefix_;

		if (!fs::exists(virtual_reg_data_dir_))
		{
			fs::create_directories(virtual_reg_data_dir_);;
		}

		if (!fs::exists(target_directory))
		{
			fs::create_directory(target_directory);

			const auto sub_key_names = enumerate_key_names(key_handle);

			for (const auto& key_name : sub_key_names)
			{
				if (key_name.starts_with(L"dr_semu"))
				{
					continue;
				}
				auto reg_command = std::wstring{ L"reg save " } + target_key_name.data() + L"\\" + key_name + L" " + target_directory + L"\\" + key_name;

				const auto is_success = create_process(reg_command);
				if (!is_success)
				{
					return false;
				}

			}

		}

		return true;
	}


	virtual_registry::virtual_registry(const std::wstring& vm_prefix)
	{
		std::error_code error_code{};
		
		this->vm_prefix_ = vm_prefix;

		auto is_success = save_root_key(L"HKLM");
		if (!is_success)
		{
			spdlog::critical("Failed to create virtual Registry\n");
		}
		is_success = save_root_key(L"HKEY_USERS");
		if (!is_success)
		{
			spdlog::critical("Failed to create virtual Registry\n");
		}


		// HKLM
		auto target_directory = virtual_reg_data_dir_ + L"\\HKLM" + L"_" + vm_prefix_;
		for (auto& path : fs::directory_iterator(target_directory))
		{
			const auto key_name = path.path().filename().wstring();
			const auto reg_command = L"reg load HKLM\\" + vm_prefix_ + L"!" + key_name + L" " + target_directory + L"\\" + key_name;

			is_success = create_process(reg_command);
			if (!is_success)
			{
				spdlog::error("Failed to load a virtual Registry\n");
			}
		}

		// HKEY_USERS
		target_directory = virtual_reg_data_dir_ + L"\\HKEY_USERS" + L"_" + vm_prefix_;
		for (auto& path : fs::directory_iterator(target_directory))
		{
			const auto key_name = path.path().filename().wstring();
			const auto reg_command = L"reg load HKEY_USERS\\" + vm_prefix_ + L"!" + key_name + L" " + target_directory + L"\\" + key_name;

			is_success = create_process(reg_command);
			if (!is_success)
			{
				spdlog::error("Failed to load a virtual Registry\n");
			}
		}

		is_loaded = true;
		virtual_reg_root = std::wstring{ LR"(HKEY_LOCAL_MACHINE\)" } +vm_prefix_;
	}
	
	bool virtual_registry::unload_virtual_key(const HKEY root_key) const
	{
		const auto root_name = root_key == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKEY_USERS";
		auto virtual_reg_names = enumerate_key_names(root_key);
		for (const auto& reg_name : virtual_reg_names)
		{
			if (reg_name.starts_with(vm_prefix_))
			{
				const auto reg_command = std::wstring{ L"reg unload " } + root_name + L"\\" + reg_name;
				const auto is_success = create_process(reg_command);
				if (!is_success)
				{
					spdlog::error("Failed to unload a virtual registry key");
				}
			}
		}

		return true;
	}

	/// Source: https://www.compuphase.com/regclone.htm
	/// Modified: Lasha Khasaia
	long virtual_registry::reg_clone_branch(const HKEY root_key_src, const HKEY root_key_dest)
	{
		auto status = ERROR_SUCCESS;
		DWORD index;
		DWORD sub_keys;
		DWORD max_key_len;
		DWORD values;
		DWORD max_value_len;
		DWORD max_data_len;
		DWORD type;

		/* get information, so that we know how much memory to allocate */
		status = RegQueryInfoKey(root_key_src, nullptr, nullptr, nullptr, &sub_keys, &max_key_len,
		                         nullptr, &values, &max_value_len, &max_data_len, nullptr, nullptr);
		if (status != ERROR_SUCCESS)
		{
			return status;
		}

		/* the name lengths do not include the '\0' terminator */
		max_key_len++;
		max_value_len++;

		/* allocate buffers, one for data and one for value & class names */
		if (max_value_len > max_key_len)
		{
			max_key_len = max_value_len;
		}

		const std::shared_ptr<TCHAR> name_ptr{new TCHAR[max_key_len]};
		std::shared_ptr<BYTE> data_ptr;
		if (name_ptr == nullptr)
		{
			return ERROR_NOT_ENOUGH_MEMORY;
		}
		if (max_data_len > 0)
		{
			data_ptr = std::shared_ptr<BYTE>{new BYTE[max_data_len]};
			if (data_ptr == nullptr)
			{
				return ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			data_ptr = nullptr;
		}

		/* first walk through the values */
		for (index = 0; index < values; index++)
		{
			auto name_size = max_key_len;
			auto data_size = max_data_len;

			status = RegEnumValue(root_key_src, index, name_ptr.get(), &name_size, nullptr, &type, data_ptr.get(),
			                      &data_size);

			if (status != ERROR_SUCCESS)
			{
				continue;
			}
			status = RegSetValueEx(root_key_dest, name_ptr.get(), 0L, type, data_ptr.get(), data_size);
			if (status != ERROR_SUCCESS)
			{
			}
		}

		/* no walk through all subkeys, and recursively call this function to copy the tree */
		for (index = 0; index < sub_keys; index++)
		{
			auto name_size = max_key_len;
			HKEY hkey_src{};
			HKEY hkey_dest{};
			status = RegEnumKeyEx(root_key_src, index, name_ptr.get(), &name_size, nullptr, nullptr, nullptr, nullptr);
			std::wstring temp_key_name = L"dr_semu_virtual_registry";
			// TODO (lasha): move regclone as a function to virtual_reg
			if (const std::wstring virtual_reg{name_ptr.get()}; virtual_reg.find(temp_key_name) != std::wstring::npos)
			{
				continue;
			}
			if (status != ERROR_SUCCESS)
			{
				continue;
			}
			status = RegOpenKeyEx(root_key_src, name_ptr.get(), 0L, KEY_READ, &hkey_src);
			if (status != ERROR_SUCCESS)
			{
				if (status == ERROR_ACCESS_DENIED)
				{
					// if ERROR_ACCESS_DENIED create empty key
					status = RegCreateKeyEx(root_key_dest, name_ptr.get(), 0L, nullptr, REG_OPTION_NON_VOLATILE,
					                        KEY_WRITE, &this->security_attributes, &hkey_dest, nullptr);
					RegCloseKey(hkey_dest);
				}
				continue;
			}

			status = RegCreateKeyExW(root_key_dest, name_ptr.get(), 0L, nullptr, REG_OPTION_NON_VOLATILE,
			                         KEY_WRITE, &this->security_attributes, &hkey_dest, nullptr);
			if (status != ERROR_SUCCESS)
			{
				//printf("0x%x %ls\n", root_key_dest, name_ptr.get());
				//MessageBox(0, 0, 0, 0);
				RegCloseKey(hkey_src);
				continue;
			}
			reg_clone_branch(hkey_src, hkey_dest);
			RegCloseKey(hkey_src);
			RegCloseKey(hkey_dest);
		}

		return status;
	}

	virtual_registry::~virtual_registry()
	{
		if (is_loaded)
		{
			const auto start_time = std::clock();

			unload_virtual_key(HKEY_LOCAL_MACHINE);
			unload_virtual_key(HKEY_USERS);
			
			spdlog::info("virtual REG unloaded successfully");
			const auto end_time = std::clock();
			const auto elapsed_secs = double(end_time - start_time) / CLOCKS_PER_SEC;
			spdlog::info("Unload time: {} second(s)", elapsed_secs);

			std::error_code err{};
			auto target_directory = virtual_reg_data_dir_ + L"\\HKLM" + L"_" + vm_prefix_;
			fs::remove_all(target_directory, err);

			target_directory = virtual_reg_data_dir_ + L"\\HKEY_USERS" + L"_" + vm_prefix_;
			fs::remove_all(target_directory, err);

		}
	}
} // namespace registry
