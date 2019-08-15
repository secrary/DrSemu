#include "virtual_reg.h"
//#include "regclone.h"

#include <aclapi.h>
#include <future>

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


	virtual_registry::virtual_registry(const std::wstring& vm_prefix)
	{
		auto is_first_time = false;

		this->security_attributes = this->get_full_access_security_attributes();
		if (security_attributes.lpSecurityDescriptor == nullptr)
		{
			spdlog::error("Failed to generate allow_all_access security descriptor");
			return;
		}

		this->vm_prefix = vm_prefix;
		this->virtual_reg_current_data_dir = virtual_reg_data_dir_ + L"\\virtual_reg_vm_" + vm_prefix;

		std::error_code error_code{};

		HKEY check_key{};
		auto status = RegOpenKey(HKEY_LOCAL_MACHINE, vm_prefix.c_str(), &check_key);
		if (status == ERROR_SUCCESS)
		{
			RegCloseKey(check_key);
			status = RegUnLoadKey(HKEY_LOCAL_MACHINE, vm_prefix.c_str());
			if (ERROR_SUCCESS != status)
			{
				spdlog::error(L"[RegUnLoadKey] failed. vm: {}. error: {}\n", vm_prefix, status);
				MessageBox(nullptr, L"[RegUnLoadKey] unload failed", nullptr, 0);
				return;
			}
			fs::remove_all(virtual_reg_current_data_dir, error_code); // noexcept
		}

		const auto virtual_reg_data = virtual_reg_data_dir_ + L"\\virtual_reg_data.dat";
		if (!fs::exists(virtual_reg_data))
		{
			spdlog::warn("Initial virtual Registry creation takes about 10-15 mins to finnish...");
			spdlog::warn("All subsequent executions will take less than a second!");
			is_first_time = true;
			if (!fs::exists(virtual_reg_data_dir_))
			{
				fs::create_directory(virtual_reg_data_dir_, error_code);
			}

			HKEY virtual_key{};
			const auto virtual_reg_temp = L"SOFTWARE\\" + this->temp_key_name;

			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, virtual_reg_temp.c_str(), 0, KEY_READ, &virtual_key);
			if (status == ERROR_SUCCESS)
			{
				RegCloseKey(virtual_key);
				spdlog::info("[Virtual_FS_REG] Removing temporary virtual registry hive");
				RegDeleteTree(HKEY_LOCAL_MACHINE, virtual_reg_temp.c_str());
			}


			const auto async_result_machine = std::async(std::launch::async, [&]()
			{
				// HKEY_LOCAL_MACHINE	
				const auto local_machine = virtual_reg_temp + L"\\HKEY_LOCAL_MACHINE";
				HKEY local_machine_key{};
				//status = RegCreateKey(HKEY_LOCAL_MACHINE, local_machine.c_str(), &local_machine_key);
				status = RegCreateKeyEx(HKEY_LOCAL_MACHINE, local_machine.c_str(), 0L, nullptr, REG_OPTION_NON_VOLATILE,
				                        KEY_WRITE, &this->security_attributes, &local_machine_key, nullptr);
				reg_clone_branch(HKEY_LOCAL_MACHINE, local_machine_key);
				RegCloseKey(local_machine_key);
			});

			const auto async_result_user = std::async(std::launch::async, [&]()
			{
				// HKEY_USERS
				const auto users_key_path = virtual_reg_temp + L"\\HKEY_USERS";
				HKEY users_key{};
				//status = RegCreateKey(HKEY_LOCAL_MACHINE, users_key_path.c_str(), &users_key);
				status = RegCreateKeyEx(HKEY_LOCAL_MACHINE, users_key_path.c_str(), 0L, nullptr,
				                        REG_OPTION_NON_VOLATILE,
				                        KEY_WRITE, &this->security_attributes, &users_key, nullptr);
				reg_clone_branch(HKEY_USERS, users_key);
				RegCloseKey(users_key);
			});

			async_result_machine.wait();
			async_result_user.wait();

			status = RegOpenKey(HKEY_LOCAL_MACHINE, virtual_reg_temp.c_str(), &virtual_key);
			if (status != ERROR_SUCCESS)
			{
				spdlog::error(L"Failed to open a key: {}\\{}", L"HKEY_LOCAL_MACHINE", virtual_reg_temp.c_str());
				return;
			}
			status = RegSaveKeyEx(virtual_key, virtual_reg_data.c_str(), nullptr, REG_LATEST_FORMAT);
			RegCloseKey(virtual_key);
			if (status != ERROR_SUCCESS)
			{
				spdlog::error("[RegSaveKeyEx] Failed\nstatus_code: {}\nlast error: {}", status, GetLastError());
				return;
			}

			status = RegDeleteTree(HKEY_LOCAL_MACHINE, virtual_reg_temp.c_str());
			if (status == ERROR_SUCCESS)
			{
				spdlog::info("[Virtual_FS_REG] Successfully removed temporary Registry hive");
			}
			else
			{
				spdlog::error("[Virtual_FS_REG] Failed to delete temporary Registry hive. last error: {}",
				              GetLastError());
			}
		}

		if (fs::exists(virtual_reg_current_data_dir))
		{
			fs::remove_all(virtual_reg_current_data_dir, error_code);
		}
		fs::create_directory(virtual_reg_current_data_dir);
		const auto current_data = virtual_reg_current_data_dir + L"\\current_reg.dat";
		fs::copy_file(virtual_reg_data, current_data);

		status = RegLoadKeyW(HKEY_LOCAL_MACHINE, vm_prefix.c_str(), current_data.c_str());
		// On Windows 10 1803, RegUnloadKey hangs whole system several minutes
		// Current solution:
		// Unload a hive and load again.
		// The problem only occures when new .dat file is created and loaded/unloaded the first time
		if (is_first_time)
		{
			// spdlog::warn("Initializing virtual Registry or refresh virtual Registry takes several minutes");
			status = RegUnLoadKey(HKEY_LOCAL_MACHINE, vm_prefix.c_str());
			status = RegLoadKeyW(HKEY_LOCAL_MACHINE, vm_prefix.c_str(), current_data.c_str());
		}
		if (status == ERROR_SUCCESS)
		{
			is_loaded = true;
		}
		virtual_reg_root = std::wstring{LR"(HKEY_LOCAL_MACHINE\)"} + vm_prefix;
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
			// RegUnLoadKey at the first time takes A LOT time and hangs whole system
			const auto status = RegUnLoadKey(HKEY_LOCAL_MACHINE, this->vm_prefix.c_str());
			if (ERROR_SUCCESS != status)
			{
				spdlog::error(L"virtual REG failed to unload: HKEY_LOCAL_MACHINE\\{}", this->vm_prefix.c_str());
				MessageBox(nullptr, L"[virtual_reg] RegUnLoadKey failed", nullptr, 0);
				return;
			}
			spdlog::info("virtual REG unloaded successfully");
			const auto end_time = std::clock();
			const auto elapsed_secs = double(end_time - start_time) / CLOCKS_PER_SEC;
			spdlog::info("Unload time: {} second(s)", elapsed_secs);
			std::error_code error_code{};
			fs::remove_all(virtual_reg_current_data_dir, error_code); // noexcept
		}
	}
} // namespace registry
