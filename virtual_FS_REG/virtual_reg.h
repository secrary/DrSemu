#pragma once

#include "includes.h"

namespace registry
{
	class virtual_registry
	{
		std::wstring vm_prefix{};
		const std::wstring virtual_reg_data_dir_ = L"virtual_reg";
		std::wstring virtual_reg_current_data_dir{};
		std::wstring temp_key_name = L"dr_semu_virtual_registry";

	public:

		SECURITY_ATTRIBUTES security_attributes{};
		bool is_loaded = false;
		std::wstring virtual_reg_root{};

		long reg_clone_branch(HKEY root_key_src, HKEY root_key_dest);
		SECURITY_ATTRIBUTES get_full_access_security_attributes() const;

		virtual_registry() = delete;
		explicit virtual_registry(const std::wstring& /*vm_prefix*/);
		~virtual_registry();

		virtual_registry(const virtual_registry& other) = delete;
		virtual_registry& operator=(const virtual_registry& other) = delete;
		virtual_registry(virtual_registry&& other) = delete;
		virtual_registry& operator=(virtual_registry&& other) = delete;
	};
} // namespace registry
