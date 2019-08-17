#include "delete.hpp"
#include "virtual_reg.h"
//#include "regclone.h"

#include <aclapi.h>
#include <future>
#include "utils.hpp"

namespace registry
{
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

		const std::unique_ptr<TCHAR> key_name{new TCHAR[MAX_PATH]};

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
			fs::create_directories(virtual_reg_data_dir_);
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
				auto reg_command = std::wstring{L"reg save "} + target_key_name.data() + L"\\" + key_name + L" " +
					target_directory + L"\\" + key_name;

				const auto is_success = create_reg_process(reg_command);
				if (!is_success)
				{
					spdlog::error(L"Command failed: {}", reg_command);
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
			const auto reg_command = L"reg load HKLM\\" + vm_prefix_ + L"!" + key_name + L" " + target_directory + L"\\"
				+ key_name;

			is_success = create_reg_process(reg_command);
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
			const auto reg_command = L"reg load HKEY_USERS\\" + vm_prefix_ + L"!" + key_name + L" " + target_directory +
				L"\\" + key_name;

			is_success = create_reg_process(reg_command);
			if (!is_success)
			{
				spdlog::error("Failed to load a virtual Registry\n");
			}
		}

		is_loaded = true;
		virtual_reg_root = std::wstring{LR"(HKEY_LOCAL_MACHINE\)"} + vm_prefix_;
	}

	bool virtual_registry::unload_virtual_key(const HKEY root_key) const
	{
		const auto root_name = root_key == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKEY_USERS";
		auto virtual_reg_names = enumerate_key_names(root_key);
		for (const auto& reg_name : virtual_reg_names)
		{
			if (reg_name.starts_with(vm_prefix_))
			{
				const auto reg_command = std::wstring{L"reg unload "} + root_name + L"\\" + reg_name;
				const auto is_success = create_reg_process(reg_command);
				if (!is_success)
				{
					spdlog::error("Failed to unload a virtual registry key");
				}
			}
		}

		return true;
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
