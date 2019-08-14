#pragma once

#include "utils.hpp"

namespace dr_semu::objects::helpers
{
	inline bool redirect_object_attributes_obj(POBJECT_ATTRIBUTES ptr_object_attributes,
		POBJECT_ATTRIBUTES new_object_attributes, std::wstring& original_name)
	{
		std::wstring object_name{};
		auto is_unnamed = false;
		const auto handle_path = dr_semu::utils::get_name_from_handle(ptr_object_attributes->RootDirectory, is_unnamed);
		if (!is_unnamed)
		{
			dr_semu::utils::unicode_string_to_wstring(ptr_object_attributes->ObjectName, object_name);
		}


		std::wstring full_path_redirected{};
		// if valid handle path
		if (!handle_path.empty())
		{
			original_name = handle_path + L"\\" + object_name;
			full_path_redirected = handle_path + L"\\" + object_name + dr_semu::shared_variables::current_vm_name;
		}
		else
		{
			original_name = object_name;
			full_path_redirected = object_name + dr_semu::shared_variables::current_vm_name;
		}

		const auto redirected_path_unicode = new UNICODE_STRING{};
		RtlCreateUnicodeString(redirected_path_unicode, const_cast<PWSTR>(full_path_redirected.c_str()));
		InitializeObjectAttributes(new_object_attributes, redirected_path_unicode, ptr_object_attributes->Attributes,
			nullptr, ptr_object_attributes->SecurityDescriptor);
		new_object_attributes->SecurityQualityOfService = ptr_object_attributes->SecurityQualityOfService;

		return true;
	}
} // namespace dr_semu::objects::helpers
