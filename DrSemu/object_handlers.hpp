#pragma once

#include "includes.h"
#include "object_helpers.hpp"
#include "filesystem_helpers.hpp"

namespace dr_semu::objects::handlers
{
	inline bool NtQueryObject_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryObject(
		//		_In_opt_ HANDLE Handle,
		//		_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
		//		_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
		//		_In_ ULONG ObjectInformationLength,
		//		_Out_opt_ PULONG ReturnLength
		//	);

		const auto handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		const auto object_information_class = OBJECT_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 1));
		const auto ptr_out_object_information = PVOID(dr_syscall_get_param(drcontext, 2));
		const auto length = ULONG(dr_syscall_get_param(drcontext, 3));
		const auto ptr_out_opt_length = PULONG(dr_syscall_get_param(drcontext, 4));

		//dr_printf("[NtQueryObject] info_class: %d\n", object_information_class);

		const auto return_status = NtQueryObject(handle, object_information_class, ptr_out_object_information, length,
		                                         ptr_out_opt_length);
		const auto is_success = NT_SUCCESS(return_status);

		//ObjectNameInformation
		if (is_success)
		{
			if (object_information_class == ObjectNameInformation && filesystem::helpers::is_handle_file_or_dir(handle))
			{
				const auto ptr_name_information = static_cast<POBJECT_NAME_INFORMATION>(ptr_out_object_information);
				std::wstring name_string;
				utils::unicode_string_to_wstring(&ptr_name_information->Name, name_string);

				// \Device\HarddiskVolumeX\Users\XXX\AppData\Local\Temp\dr_semu_1\folder\test_file.temp => \Device\HarddiskVolumeX\folder\test_file.temp
				filesystem::helpers::virtual_to_original_hard_disk_volume(name_string);
				memset(ptr_name_information->Name.Buffer, 0, ptr_name_information->Name.Length);
				const auto name_size = name_string.length() * sizeof(TCHAR);
				memcpy_s(ptr_name_information->Name.Buffer, ptr_name_information->Name.MaximumLength,
				         name_string.c_str(), name_size);
				ptr_name_information->Name.Length = name_size;
				ptr_name_information->Name.MaximumLength = name_size + sizeof(TCHAR);
			}
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_RESULT::SKIP;
	}

	inline bool NtWaitForSingleObject_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtWaitForSingleObject(
		//		_In_ HANDLE Handle,
		//		_In_ BOOLEAN Alertable,
		//		_In_opt_ PLARGE_INTEGER Timeout
		//	);

		const auto handle = HANDLE(dr_syscall_get_param(drcontext, 0));

		//dr_printf("[NtWaitForSingleObject] handle: 0x%lx\n", handle);

		return SYSCALL_RESULT::CONTINUE;
	}

	inline bool NtOpenEvent_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenEvent(
		//		_Out_ PHANDLE EventHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes
		//	);

		const auto ptr_out_event_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));

		if (ptr_object_attributes != nullptr)
		{
			HANDLE temporary_handle{};
			auto return_status = NtOpenEvent(&temporary_handle, desired_access, ptr_object_attributes);
			if (NT_SUCCESS(return_status))
			{
				CloseHandle(temporary_handle);
				return SYSCALL_RESULT::CONTINUE; // nothing to change
			}

			std::wstring original_name{};
			OBJECT_ATTRIBUTES redirected_object_attributes{};
			const auto is_valid = helpers::redirect_object_attributes_obj(
				ptr_object_attributes, &redirected_object_attributes, original_name);

			return_status = NtOpenEvent(ptr_out_event_handle, desired_access, &redirected_object_attributes);
			delete redirected_object_attributes.ObjectName;

			json open_event;
			const std::string original_name_ascii(original_name.begin(), original_name.end());
			open_event["NtOpenEvent"]["before"] =
			{
				{"name", original_name_ascii.c_str()},
			};
			open_event["NtOpenEvent"]["success"] = NT_SUCCESS(return_status);

			shared_variables::json_concurrent_vector.push_back(open_event);
			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_RESULT::SKIP;
		}

		return SYSCALL_RESULT::CONTINUE;
	}

	inline bool NtCreateEvent_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateEvent(
		//		_Out_ PHANDLE EventHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ EVENT_TYPE EventType,
		//		_In_ BOOLEAN InitialState
		//	);

		const auto ptr_out_event_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_opt_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		const auto event_type = EVENT_TYPE(dr_syscall_get_param(drcontext, 3));
		const auto initial_state = BOOLEAN(dr_syscall_get_param(drcontext, 4));

		if (ptr_opt_object_attributes != nullptr)
		{
			HANDLE temporary_handle{};
			auto return_status = NtOpenEvent(&temporary_handle, desired_access, ptr_opt_object_attributes);
			if (NT_SUCCESS(return_status))
			{
				CloseHandle(temporary_handle);
				return SYSCALL_RESULT::CONTINUE; // nothing to change
			}

			std::wstring original_name{};
			OBJECT_ATTRIBUTES redirected_object_attributes{};
			const auto is_valid = helpers::redirect_object_attributes_obj(
				ptr_opt_object_attributes, &redirected_object_attributes, original_name);

			return_status = NtCreateEvent(ptr_out_event_handle, desired_access, &redirected_object_attributes,
			                              event_type, initial_state);
			delete redirected_object_attributes.ObjectName;

			json create_event;
			const std::string original_name_ascii(original_name.begin(), original_name.end());
			create_event["NtCreateEvent"]["before"] = {
				{"name", original_name_ascii.c_str()},
			};
			create_event["NtCreateEvent"]["success"] = NT_SUCCESS(return_status);

			shared_variables::json_concurrent_vector.push_back(create_event);

			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_RESULT::SKIP;
		}

		return SYSCALL_RESULT::CONTINUE;
	}

	inline bool NtOpenSemaphore_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenSemaphore(
		//		_Out_ PHANDLE SemaphoreHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes
		//	);

		const auto ptr_out_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));

		if (ptr_object_attributes != nullptr)
		{
			HANDLE temporary_handle{};
			auto return_status = NtOpenSemaphore(&temporary_handle, desired_access, ptr_object_attributes);
			if (NT_SUCCESS(return_status))
			{
				CloseHandle(temporary_handle);
				return SYSCALL_RESULT::CONTINUE; // nothing to change
			}

			std::wstring original_name{};
			OBJECT_ATTRIBUTES redirected_object_attributes{};
			const auto is_valid = helpers::redirect_object_attributes_obj(
				ptr_object_attributes, &redirected_object_attributes, original_name);

			return_status = NtOpenSemaphore(ptr_out_handle, desired_access, &redirected_object_attributes);
			delete redirected_object_attributes.ObjectName;

			json open_semaphore;
			const std::string original_name_ascii(original_name.begin(), original_name.end());
			open_semaphore["NtOpenSemaphore"]["before"] =
			{
				{"name", original_name_ascii.c_str()},
			};
			open_semaphore["NtOpenSemaphore"]["success"] = NT_SUCCESS(return_status);

			shared_variables::json_concurrent_vector.push_back(open_semaphore);
			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_RESULT::SKIP;
		}

		return SYSCALL_RESULT::CONTINUE;
	}

	inline bool NtCreateSemaphore_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateSemaphore(
		//		_Out_ PHANDLE SemaphoreHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ LONG InitialCount,
		//		_In_ LONG MaximumCount
		//	);

		const auto ptr_out_semaphore_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_opt_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		const auto initial_count = LONG(dr_syscall_get_param(drcontext, 3));
		const auto maximum_count = LONG(dr_syscall_get_param(drcontext, 4));

		if (ptr_opt_object_attributes != nullptr)
		{
			HANDLE temporary_handle{};
			auto return_status = NtOpenSemaphore(&temporary_handle, desired_access, ptr_opt_object_attributes);
			// if Semaphore ALREADY exists, most likely it's something related to system
			// all Semaphores from current sample and other samples should ALREADY be renamed
			if (NT_SUCCESS(return_status))
			{
				CloseHandle(temporary_handle);
				return SYSCALL_RESULT::CONTINUE; // nothing to change
			}

			std::wstring original_name{};
			OBJECT_ATTRIBUTES redirected_object_attributes{};
			const auto is_valid = helpers::redirect_object_attributes_obj(
				ptr_opt_object_attributes, &redirected_object_attributes, original_name);

			return_status = NtCreateSemaphore(ptr_out_semaphore_handle, desired_access, &redirected_object_attributes,
			                                  initial_count, maximum_count);
			delete redirected_object_attributes.ObjectName;

			json create_semaphore;
			const std::string original_name_ascii(original_name.begin(), original_name.end());
			create_semaphore["NtCreateSemaphore"]["before"] = {
				{"name", original_name_ascii.c_str()},
			};
			create_semaphore["NtCreateSemaphore"]["success"] = NT_SUCCESS(return_status);

			shared_variables::json_concurrent_vector.push_back(create_semaphore);

			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_RESULT::SKIP;
		}

		return SYSCALL_RESULT::CONTINUE;
	}

	inline bool NtCreateMailslotFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateMailslotFile(
		//		_Out_ PHANDLE FileHandle,
		//		_In_ ULONG DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_ ULONG CreateOptions,
		//		_In_ ULONG MailslotQuota,
		//		_In_ ULONG MaximumMessageSize,
		//		_In_ PLARGE_INTEGER ReadTimeout
		//	);

		const auto ptr_out_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_opt_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		const auto ptr_out_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 3));
		const auto creation_options = ULONG(dr_syscall_get_param(drcontext, 4));
		const auto quota = ULONG(dr_syscall_get_param(drcontext, 5));
		const auto max_message_size = ULONG(dr_syscall_get_param(drcontext, 6));
		const auto ptr_read_timeout = PLARGE_INTEGER(dr_syscall_get_param(drcontext, 7));

		if (ptr_opt_object_attributes == nullptr)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_RESULT::SKIP;
		}

		std::wstring original_name{};
		OBJECT_ATTRIBUTES redirected_object_attributes{};
		const auto is_valid = helpers::redirect_object_attributes_obj(
			ptr_opt_object_attributes, &redirected_object_attributes, original_name);

		const auto return_status = NtCreateMailslotFile(ptr_out_handle, desired_access, &redirected_object_attributes,
		                                                ptr_out_status_block, creation_options, quota, max_message_size,
		                                                ptr_read_timeout);
		delete redirected_object_attributes.ObjectName;
		const auto is_success = NT_SUCCESS(return_status);

		json create_mailslot;
		const std::string original_name_ascii(original_name.begin(), original_name.end());
		create_mailslot["NtCreateMailslotFile"]["before"] = {
			{"name", original_name_ascii.c_str()},
		};
		create_mailslot["NtCreateMailslotFile"]["success"] = is_success;

		shared_variables::json_concurrent_vector.push_back(create_mailslot);
		return SYSCALL_RESULT::SKIP;
	}

	inline bool NtCreateMutant_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateMutant(
		//		_Out_ PHANDLE MutantHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ BOOLEAN InitialOwner
		//	);

		const auto ptr_out_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // MutantHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_opt_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		// ObjectAttributes
		const auto owner = BOOLEAN(dr_syscall_get_param(drcontext, 3)); // InitialOwner

		if (ptr_opt_object_attributes != nullptr)
		{
			HANDLE temporary_handle{};
			auto return_status = NtOpenMutant(&temporary_handle, desired_access, ptr_opt_object_attributes);
			// if mutex ALREADY exists, most likely it's something related to system
			// all mutexes from current sample and other samples should ALREADY be renamed
			if (NT_SUCCESS(return_status))
			{
				CloseHandle(temporary_handle);
				return SYSCALL_RESULT::CONTINUE; // nothing to change
			}

			std::wstring original_name{};
			OBJECT_ATTRIBUTES redirected_object_attributes{};
			const auto is_valid = helpers::redirect_object_attributes_obj(
				ptr_opt_object_attributes, &redirected_object_attributes, original_name);

			return_status = NtCreateMutant(ptr_out_handle, desired_access, &redirected_object_attributes, owner);
			delete redirected_object_attributes.ObjectName;

			json create_mutex;
			const std::string original_name_ascii(original_name.begin(), original_name.end());
			create_mutex["NtCreateMutant"]["before"] = {
				{"name", original_name_ascii.c_str()},
			};
			create_mutex["NtCreateMutant"]["success"] = NT_SUCCESS(return_status);

			shared_variables::json_concurrent_vector.push_back(create_mutex);

			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_RESULT::SKIP;
		}

		return SYSCALL_RESULT::CONTINUE;
	}

	inline bool NtOpenMutant_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenMutant(
		//		_Out_ PHANDLE MutantHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes
		//	);

		const auto ptr_out_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));

		if (ptr_object_attributes != nullptr)
		{
			HANDLE temporary_handle{};
			auto return_status = NtOpenMutant(&temporary_handle, desired_access, ptr_object_attributes);
			// if mutex ALREADY exists in ORIGINAL form, most likely it's something related to a system.
			// all mutexes from current sample and other samples should ALREADY be renamed.
			if (NT_SUCCESS(return_status))
			{
				CloseHandle(temporary_handle);
				return SYSCALL_RESULT::CONTINUE; // nothing to change
			}


			std::wstring original_name{};
			OBJECT_ATTRIBUTES redirected_object_attributes{};
			const auto is_valid = helpers::redirect_object_attributes_obj(
				ptr_object_attributes, &redirected_object_attributes, original_name);

			return_status = NtOpenMutant(ptr_out_handle, desired_access, &redirected_object_attributes);
			delete redirected_object_attributes.ObjectName;

			json open_mutex;
			const std::string original_name_ascii(original_name.begin(), original_name.end());
			open_mutex["NtOpenMutant"]["before"] =
			{
				{"name", original_name_ascii.c_str()},
			};
			open_mutex["NtOpenMutant"]["success"] = NT_SUCCESS(return_status);

			shared_variables::json_concurrent_vector.push_back(open_mutex);
			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_RESULT::SKIP;
		}

		return SYSCALL_RESULT::CONTINUE;
	}
} // namespace dr_semu::objects::handlers
