#pragma once

#include "includes.h"

#include "registry_helpers.hpp"

namespace dr_semu::registry::handlers
{
	inline bool NtQueryOpenSubKeysEx_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryOpenSubKeysEx(
		//		_In_ POBJECT_ATTRIBUTES TargetKey,
		//		_In_ ULONG BufferLength,
		//		_Out_writes_bytes_(BufferLength) PVOID Buffer,
		//		_Out_ PULONG RequiredSize
		//	);

		const auto ptr_target_key = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0)); // TargetKey
		const auto buffer_length = ULONG(dr_syscall_get_param(drcontext, 1)); // BufferLength
		const auto ptr_out_buffer = PVOID(dr_syscall_get_param(drcontext, 2)); // Buffer
		const auto ptr_out_required_size = PULONG(dr_syscall_get_param(drcontext, 3)); // RequiredSize

		auto is_virtual_handle = false;
		auto is_deleted = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::get_virtual_object_attributes_reg(
			ptr_target_key, true, is_virtual_handle, trace_string, is_deleted);

		const auto return_status = NtQueryOpenSubKeysEx(
			is_deleted ? ptr_target_key : &virtual_object_attributes, buffer_length, ptr_out_buffer,
			ptr_out_required_size);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtQueryOpenSubKeys_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryOpenSubKeys(
		//		_In_ POBJECT_ATTRIBUTES TargetKey,
		//		_Out_ PULONG HandleCount
		//	);

		const auto ptr_target_key = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0)); // TargetKey
		const auto ptr_out_handle_count = PULONG(dr_syscall_get_param(drcontext, 1)); // HandleCount

		auto is_virtual_handle = false;
		auto is_deleted = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::get_virtual_object_attributes_reg(
			ptr_target_key, true, is_virtual_handle, trace_string, is_deleted);

		const auto return_status = NtQueryOpenSubKeys(
			is_deleted ? ptr_target_key : &virtual_object_attributes, ptr_out_handle_count);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}


	inline bool NtQueryMultipleValueKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryMultipleValueKey(
		//		_In_ HANDLE KeyHandle,
		//		_Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
		//		_In_ ULONG EntryCount,
		//		_Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
		//		_Inout_ PULONG BufferLength,
		//		_Out_opt_ PULONG RequiredBufferLength
		//	);

		// details: https://web.archive.org/web/20190528130139/https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-ntquerymultiplevaluekey

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto value_entries = PKEY_VALUE_ENTRY(dr_syscall_get_param(drcontext, 1)); // ValueEntries
		const auto entry_count = ULONG(dr_syscall_get_param(drcontext, 2)); // EntryCount
		const auto value_buffer = PVOID(dr_syscall_get_param(drcontext, 3)); // ValueBuffer
		const auto buffer_length = PULONG(dr_syscall_get_param(drcontext, 4)); // BufferLength
		const auto required_buffer_length = PULONG(dr_syscall_get_param(drcontext, 5)); // RequiredBufferLength

		HKEY virtual_handle{};
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(HKEY(key_handle), virtual_handle, is_root);

		const auto return_result = NtQueryMultipleValueKey(is_virtual_handle ? virtual_handle : key_handle,
		                                                   value_entries, entry_count, value_buffer, buffer_length,
		                                                   required_buffer_length);

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_result);
		return SYSCALL_SKIP;
	}


	inline bool NtLockRegistryKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtLockRegistryKey(
		//		_In_ HANDLE KeyHandle
		//	);

		// details: https://tyranidslair.blogspot.com/2017/07/locking-your-registry-keys-for-fun-and.html
		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle

		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD);
		return SYSCALL_SKIP;
	}

	inline bool NtLoadKeyEx_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtLoadKeyEx(
		//		_In_ POBJECT_ATTRIBUTES TargetKey,
		//		_In_ POBJECT_ATTRIBUTES SourceFile,
		//		_In_ ULONG Flags,
		//		_In_opt_ HANDLE TrustClassKey,
		//		_In_opt_ HANDLE Event,
		//		_In_opt_ ACCESS_MASK DesiredAccess,
		//		_Out_opt_ PHANDLE RootHandle,
		//		_Out_opt_ PIO_STATUS_BLOCK IoStatus
		//	);

		const auto ptr_target_key = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0)); // TargetKey
		const auto ptr_source_file = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 1)); // SourceFile
		const auto flags = ULONG(dr_syscall_get_param(drcontext, 2)); // Flags
		const auto trust_class_key = HANDLE(dr_syscall_get_param(drcontext, 3)); // TrustClassKey
		const auto event_handle = HANDLE(dr_syscall_get_param(drcontext, 4)); // Event
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 5)); // DesiredAccess
		const auto ptr_out_root_handle = PHANDLE(dr_syscall_get_param(drcontext, 6)); // RootHandle
		const auto ptr_out_io_status = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 7)); // IoStatus

		// The calling process must have the SE_RESTORE_NAME and SE_BACKUP_NAME privileges
		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD);
		return SYSCALL_SKIP;
	}

	inline bool NtLoadKey2_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtLoadKey2(
		//		_In_ POBJECT_ATTRIBUTES TargetKey,
		//		_In_ POBJECT_ATTRIBUTES SourceFile,
		//		_In_ ULONG Flags
		//	);

		const auto ptr_target_key = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0)); // TargetKey
		const auto ptr_source_file = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 1)); // SourceFile
		const auto flags = ULONG(dr_syscall_get_param(drcontext, 2)); // Flags

		// The calling process must have the SE_RESTORE_NAME and SE_BACKUP_NAME privileges
		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD);
		return SYSCALL_SKIP;
	}

	inline bool NtSaveKeyEx_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSaveKeyEx(
		//		_In_ HANDLE KeyHandle,
		//		_In_ HANDLE FileHandle,
		//		_In_ ULONG Format
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto file_handle = HANDLE(dr_syscall_get_param(drcontext, 1)); // FileHandle
		const auto format = ULONG(dr_syscall_get_param(drcontext, 2)); // Format


		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD); // SE_BACKUP_NAME  is required
		return SYSCALL_SKIP;
	}

	inline bool NtSaveKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSaveKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ HANDLE FileHandle
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto file_handle = HANDLE(dr_syscall_get_param(drcontext, 1)); // FileHandle

		// since key_handle is a file handle on vFS and not reg_key handle NtSaveKey returns "invalid handle" error

		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD); // SE_BACKUP_NAME  is required
		return SYSCALL_SKIP;
	}

	inline bool NtLoadKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtLoadKey(
		//		_In_ POBJECT_ATTRIBUTES TargetKey,
		//		_In_ POBJECT_ATTRIBUTES SourceFile
		//	);

		// Creates a subkey under HKEY_USERS or HKEY_LOCAL_MACHINE and loads the data from the specified registry hive into that subkey.
		const auto ptr_target_key = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0)); // TargetKey
		const auto ptr_source_file = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 1)); // TargetKey

		// The calling process must have the SE_RESTORE_NAME and SE_BACKUP_NAME privileges
		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD);
		return SYSCALL_SKIP;
	}

	inline bool NtInitializeRegistry_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtInitializeRegistry(
		//		_In_ USHORT BootCondition
		//	);

		//const auto boot_condition = USHORT(dr_syscall_get_param(drcontext, 0)); // BootCondition

		dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
		return SYSCALL_SKIP;
	}

	inline bool NtFreezeRegistry_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtFreezeRegistry(
		//		_In_ ULONG TimeOutInSeconds
		//	);

		const auto time_out_in_seconds = ULONG(dr_syscall_get_param(drcontext, 0)); // TimeOutInSeconds

		dr_syscall_set_result(drcontext, STATUS_SUCCESS);
		return SYSCALL_SKIP;
	}

	inline bool NtFlushKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtFlushKey(
		//		_In_ HANDLE KeyHandle
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle

		HKEY virtual_key{};
		auto is_root = false;
		const auto is_virtual_key = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_key, is_root);

		const auto return_result = NtFlushKey(is_virtual_key ? virtual_key : key_handle);

		if (is_virtual_key)
		{
			RegCloseKey(virtual_key);
		}

		dr_syscall_set_result(drcontext, return_result);
		return SYSCALL_SKIP;
	}

	inline bool NtOpenKeyTransactedEx_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenKeyTransactedEx(
		//		_Out_ PHANDLE KeyHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ ULONG OpenOptions,
		//		_In_ HANDLE TransactionHandle
		//	);

		const auto ptr_out_key_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		const auto open_options = ULONG(dr_syscall_get_param(drcontext, 3)); // OpenOptions
		const auto transaction_handle = HANDLE(dr_syscall_get_param(drcontext, 4)); // TransactionHandle

#if defined(_WIN64)
		const bool cross_access = desired_access & KEY_WOW64_32KEY;
#else
		const auto cross_access = (desired_access & KEY_WOW64_64KEY) != 0U;
#endif

		auto is_virtual_handle = false;
		auto is_deleted = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::
			get_virtual_object_attributes_reg(ptr_object_attributes, cross_access, is_virtual_handle, trace_string,
			                                  is_deleted);

		const auto return_status = NtOpenKeyTransactedEx(ptr_out_key_handle, desired_access,
		                                                 is_deleted
			                                                 ? ptr_object_attributes
			                                                 : &virtual_object_attributes, open_options,
		                                                 transaction_handle);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtOpenKeyTransacted_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenKeyTransacted(
		//		_Out_ PHANDLE KeyHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ HANDLE TransactionHandle
		//	);

		const auto ptr_out_key_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		const auto transaction_handle = HANDLE(dr_syscall_get_param(drcontext, 3)); // TransactionHandle

#if defined(_WIN64)
		const bool cross_access = desired_access & KEY_WOW64_32KEY;
#else
		const auto cross_access = (desired_access & KEY_WOW64_64KEY) != 0U;
#endif

		auto is_virtual_handle = false;
		auto is_deleted = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::
			get_virtual_object_attributes_reg(ptr_object_attributes, cross_access, is_virtual_handle, trace_string,
			                                  is_deleted);

		const auto return_status = NtOpenKeyTransacted(ptr_out_key_handle, desired_access,
		                                               is_deleted ? ptr_object_attributes : &virtual_object_attributes,
		                                               transaction_handle);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateKeyTransacted_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateKeyTransacted(
		//		_Out_ PHANDLE KeyHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Reserved_ ULONG TitleIndex,
		//		_In_opt_ PUNICODE_STRING Class,
		//		_In_ ULONG CreateOptions,
		//		_In_ HANDLE TransactionHandle,
		//		_Out_opt_ PULONG Disposition
		//	);

		const auto ptr_out_key_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		const auto title_index = ULONG(dr_syscall_get_param(drcontext, 3)); // TitleIndex
		const auto reg_class = PUNICODE_STRING(dr_syscall_get_param(drcontext, 4)); // Class
		const auto creation_options = ULONG(dr_syscall_get_param(drcontext, 5)); // CreateOptions
		// Pointer to a variable that receives a value indicating whether a new key was created or an existing one opened.
		const auto transaction_handle = HANDLE(dr_syscall_get_param(drcontext, 6)); // TransactionHandle
		const auto ptr_out_disposition = PULONG(dr_syscall_get_param(drcontext, 7)); // Disposition

#if defined(_WIN64)
		const bool cross_access = desired_access & KEY_WOW64_32KEY;
#else
		const auto cross_access = (desired_access & KEY_WOW64_64KEY) != 0U;
#endif

		auto is_virtual_handle = false;
		auto is_deleted = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::
			get_virtual_object_attributes_reg(ptr_object_attributes, cross_access, is_virtual_handle, trace_string,
			                                  is_deleted);

		const auto return_result = NtCreateKeyTransacted(ptr_out_key_handle, desired_access,
		                                                 is_deleted
			                                                 ? ptr_object_attributes
			                                                 : &virtual_object_attributes,
		                                                 title_index, reg_class, creation_options, transaction_handle,
		                                                 ptr_out_disposition);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		dr_syscall_set_result(drcontext, return_result);
		return SYSCALL_SKIP;
	}

	inline bool NtCompressKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCompressKey(
		//		_In_ HANDLE Key
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle

		HKEY virtual_key{};
		auto is_root = false;
		const auto is_virtual_key = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_key, is_root);

		const auto return_status = NtCompressKey(is_virtual_key ? virtual_key : key_handle);

		if (is_virtual_key)
		{
			RegCloseKey(virtual_key);
		}

		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD); // or STATUS_NOT_IMPLEMENTED

		return SYSCALL_SKIP;
	}

	inline bool NtCompactKeys_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCompactKeys(
		//		_In_ ULONG Count,
		//		_In_reads_(Count) HANDLE KeyArray[]
		//	);

		const auto key_handle = ULONG(dr_syscall_get_param(drcontext, 0)); // Count
		const auto ptr_key_array = PHANDLE(dr_syscall_get_param(drcontext, 1)); // KeyArray

		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD);
		return SYSCALL_SKIP;
	}

	inline bool NtNotifyChangeMultipleKeys_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtNotifyChangeMultipleKeys(
		//		_In_ HANDLE MasterKeyHandle,
		//		_In_opt_ ULONG Count,
		//		_In_reads_opt_(Count) OBJECT_ATTRIBUTES SubordinateObjects[],
		//		_In_opt_ HANDLE Event,
		//		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		//		_In_opt_ PVOID ApcContext,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_ ULONG CompletionFilter,
		//		_In_ BOOLEAN WatchTree,
		//		_Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
		//		_In_ ULONG BufferSize,
		//		_In_ BOOLEAN Asynchronous
		//	);

		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 6)); // IoStatusBlock

		ptr_io_status_block->Status = STATUS_SUCCESS;
		ptr_io_status_block->Information = 0;
		ptr_io_status_block->Pointer = nullptr;

		dr_syscall_set_result(drcontext, STATUS_PENDING);
		return SYSCALL_SKIP;
	}

	inline bool NtNotifyChangeKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtNotifyChangeKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_opt_ HANDLE Event,
		//		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		//		_In_opt_ PVOID ApcContext,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_ ULONG CompletionFilter,
		//		_In_ BOOLEAN WatchTree,
		//		_Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
		//		_In_ ULONG BufferSize,
		//		_In_ BOOLEAN Asynchronous
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto key_event = HANDLE(dr_syscall_get_param(drcontext, 1)); // Event
		const auto ptr_apc_routine = PIO_APC_ROUTINE(dr_syscall_get_param(drcontext, 2)); // ApcRoutine
		const auto apt_context = PVOID(dr_syscall_get_param(drcontext, 3)); // ApcContext
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 4)); // IoStatusBlock
		const auto completion_filter = ULONG(dr_syscall_get_param(drcontext, 5)); // CompletionFilter
		const auto watch_tree = BOOLEAN(dr_syscall_get_param(drcontext, 6)); // WatchTree
		const auto buffer = PVOID(dr_syscall_get_param(drcontext, 7)); // Buffer
		const auto buffer_size = ULONG(dr_syscall_get_param(drcontext, 8)); // BufferSize
		const auto asynchronous = BOOLEAN(dr_syscall_get_param(drcontext, 9)); // Asynchronous

		HKEY virtual_handle{};
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_handle,
		                                                           is_root);

		const auto return_status = NtNotifyChangeKey(is_virtual_handle ? virtual_handle : key_handle, key_event,
		                                             ptr_apc_routine, apt_context, ptr_io_status_block,
		                                             completion_filter, watch_tree, buffer, buffer_size, asynchronous);

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtSetValueKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSetValueKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ PUNICODE_STRING ValueName,
		//		_In_opt_ ULONG TitleIndex,
		//		_In_ ULONG Type,
		//		_In_reads_bytes_opt_(DataSize) PVOID Data,
		//		_In_ ULONG DataSize
		//	);

		// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwsetvaluekey

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto value_name = PUNICODE_STRING(dr_syscall_get_param(drcontext, 1)); // ValueName
		const auto title_index = ULONG(dr_syscall_get_param(drcontext, 2)); // TitleIndex
		const auto type = ULONG(dr_syscall_get_param(drcontext, 3)); // Type
		const auto data = PVOID(dr_syscall_get_param(drcontext, 4)); // Data
		const auto data_size = ULONG(dr_syscall_get_param(drcontext, 5)); // DataSize

		HKEY virtual_handle{};
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_handle,
		                                                           is_root);

		const auto return_status = NtSetValueKey(is_virtual_handle ? virtual_handle : key_handle, value_name,
		                                         title_index, type, data, data_size);

		auto is_unnamed = false;
		const auto handle_name = utils::get_name_from_handle(is_virtual_handle ? virtual_handle : key_handle,
		                                                     is_unnamed);

		//dr_printf("x: %ls\\%ls\n", handle_name.c_str(), value_name->Buffer);

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtEnumerateValueKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtEnumerateValueKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ ULONG Index,
		//		_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		//		_Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
		//		_In_ ULONG Length,
		//		_Out_ PULONG ResultLength
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle (file_handle)
		const auto index = ULONG(dr_syscall_get_param(drcontext, 1)); // Index
		const auto value_information_class = KEY_VALUE_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 2));
		// KeyValueInformationClass
		const auto ptr_out_value_information = PVOID(dr_syscall_get_param(drcontext, 3)); // KeyValueInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 4)); // Length
		const auto ptr_out_result_length = PULONG(dr_syscall_get_param(drcontext, 5)); // ResultLength

		HKEY virtual_handle = nullptr;
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_handle,
		                                                           is_root);

		const auto result_status = NtEnumerateValueKey(is_virtual_handle ? virtual_handle : key_handle,
		                                               index, value_information_class, ptr_out_value_information,
		                                               length, ptr_out_result_length);

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}

		dr_syscall_set_result(drcontext, result_status);
		return SYSCALL_SKIP;
	}

	inline bool enumerate_key_internal(void* drcontext, HANDLE key_handle, const ULONG index,
	                                   KEY_INFORMATION_CLASS key_information_class,
	                                   /*_Out_writes_bytes_opt_*/ PVOID ptr_out_key_information, ULONG length,
	                                   PULONG ptr_out_result_length,
	                                   const bool is_valid_index)
	{
		DWORD result_status = STATUS_SUCCESS;

		// if a handle is not under virtual_reg => create a new handle under virtual_reg
		HKEY virtual_reg_handle = nullptr;

		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_reg_handle,
		                                                           is_root);

		if (is_valid_index)
		{
			result_status = NtEnumerateKey(is_virtual_handle ? virtual_reg_handle : key_handle, index,
			                               key_information_class,
			                               ptr_out_key_information, length, ptr_out_result_length);
		}

		else
		{
			result_status = NtQueryKey(is_virtual_handle ? virtual_reg_handle : key_handle, key_information_class,
			                           ptr_out_key_information, length, ptr_out_result_length);
			// return "real" path
			if (NT_SUCCESS(result_status) && (ptr_out_key_information != nullptr))
			{
				if (key_information_class == KeyNameInformation)
				{
					// reverted name always should be smaller
					auto ptr_name_information = static_cast<PKEY_NAME_INFORMATION>(ptr_out_key_information);
					const std::wstring name(ptr_name_information->Name,
					                        ptr_name_information->NameLength / sizeof(WCHAR));

					const auto reverted_name = helpers::original_to_virtual_reg(name, is_root, true);

					memset(ptr_name_information->Name, 0, ptr_name_information->NameLength);
					ptr_name_information->NameLength = reverted_name.length() * sizeof(WCHAR);
					memcpy_s(ptr_name_information->Name, ptr_name_information->NameLength, reverted_name.data(),
					         reverted_name.length() * sizeof(WCHAR));
				}
				else if (key_information_class == KeyBasicInformation)
				{
					auto ptr_basic_information = static_cast<PKEY_BASIC_INFORMATION>(ptr_out_key_information);
					const std::wstring name(ptr_basic_information->Name,
					                        ptr_basic_information->NameLength / sizeof(WCHAR));
					const auto reverted_name = helpers::original_to_virtual_reg(name, is_root, true);

					memset(ptr_basic_information->Name, 0, ptr_basic_information->NameLength);
					ptr_basic_information->NameLength = reverted_name.length() * sizeof(WCHAR);
					memcpy_s(ptr_basic_information->Name, ptr_basic_information->NameLength, reverted_name.data(),
					         reverted_name.length() * sizeof(WCHAR));
				}
				else if (key_information_class == KeyCachedInformation)
				{
					auto ptr_cached_information = static_cast<PKEY_CACHED_INFORMATION>(ptr_out_key_information);
					const std::wstring name(ptr_cached_information->Name,
					                        ptr_cached_information->NameLength / sizeof(WCHAR));
					const auto reverted_name = helpers::original_to_virtual_reg(name, is_root, true);

					memset(ptr_cached_information->Name, 0, ptr_cached_information->NameLength);
					ptr_cached_information->NameLength = reverted_name.length() * sizeof(WCHAR);
					memcpy_s(ptr_cached_information->Name, ptr_cached_information->NameLength, reverted_name.data(),
					         reverted_name.length() * sizeof(WCHAR));
				}
				else if (key_information_class == KeyNodeInformation)
				{
					auto ptr_node_information = static_cast<PKEY_NODE_INFORMATION>(ptr_out_key_information);
					const std::wstring name(ptr_node_information->Name,
					                        ptr_node_information->NameLength / sizeof(WCHAR));
					const auto reverted_name = helpers::original_to_virtual_reg(name, is_root, true);

					memset(ptr_node_information->Name, 0, ptr_node_information->NameLength);
					ptr_node_information->NameLength = reverted_name.length() * sizeof(WCHAR);
					memcpy_s(ptr_node_information->Name, ptr_node_information->NameLength, reverted_name.data(),
					         reverted_name.length() * sizeof(WCHAR));
				}
			}
		}

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_reg_handle);
		}

		/// trace call
		auto is_deleted = false;
		const auto key_path = helpers::get_path_from_handle_reg(key_handle, is_deleted);
		const auto original_path = helpers::original_to_virtual_reg(key_path, is_root, true);
		std::string original_ascii(original_path.begin(), original_path.end());
		json enumerate_key;
		// NtEnumerateKey and NtQueryKey
		std::string function_name = is_valid_index ? "NtEnumerateKey" : "NtQueryKey";
		enumerate_key[function_name]["before"] = {
			{"key_path", original_ascii.c_str()},
		};
		enumerate_key[function_name]["success"] = NT_SUCCESS(result_status);

		//if (!NT_SUCCESS(result_status))
		//	dr_printf("enum_key: %ls\nret: 0x%lx\n", original_path.c_str(), result_status);

		shared_variables::json_concurrent_vector.push_back(enumerate_key);

		dr_syscall_set_result(drcontext, result_status);
		return SYSCALL_SKIP;
	}

	inline bool NtEnumerateKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtEnumerateKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ ULONG Index,
		//		_In_ KEY_INFORMATION_CLASS KeyInformationClass,
		//		_Out_writes_bytes_opt_(Length) PVOID KeyInformation,
		//		_In_ ULONG Length,
		//		_Out_ PULONG ResultLength
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle (file_handle)
		const auto index = ULONG(dr_syscall_get_param(drcontext, 1)); // Index
		const auto key_information_class = KEY_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 2));
		// KeyInformationClass
		const auto ptr_out_key_information = PVOID(dr_syscall_get_param(drcontext, 3)); // KeyInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 4)); // Length
		const auto ptr_out_result_length = PULONG(dr_syscall_get_param(drcontext, 5)); // ResultLength

		return enumerate_key_internal(drcontext, key_handle, index, key_information_class, ptr_out_key_information,
		                              length, ptr_out_result_length, true);
	}

	inline bool NtQueryKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ KEY_INFORMATION_CLASS KeyInformationClass,
		//		_Out_writes_bytes_opt_(Length) PVOID KeyInformation,
		//		_In_ ULONG Length,
		//		_Out_ PULONG ResultLength
		//	);


		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle (file_handle)
		const auto key_information_class = KEY_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 1));
		const auto ptr_out_key_information = PVOID(dr_syscall_get_param(drcontext, 2)); // KeyInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 3)); // Length
		const auto ptr_out_result_length = PULONG(dr_syscall_get_param(drcontext, 4)); // ResultLength

		return enumerate_key_internal(drcontext, key_handle, 0, key_information_class, ptr_out_key_information,
		                              length, ptr_out_result_length, false);
	}

	inline bool NtQueryValueKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryValueKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ PUNICODE_STRING ValueName,
		//		_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		//		_Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
		//		_In_ ULONG Length,
		//		_Out_ PULONG ResultLength
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto value_name = PUNICODE_STRING(dr_syscall_get_param(drcontext, 1)); // ValueName
		const auto information_class = KEY_VALUE_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 2));
		const auto ptr_out_key_value_information = PVOID(dr_syscall_get_param(drcontext, 3)); // KeyValueInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 4)); // Length
		const auto ptr_out_result_length = PULONG(dr_syscall_get_param(drcontext, 5)); // ResultLength

		HKEY virtual_handle = nullptr;
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_handle,
		                                                           is_root);

		const auto return_status = NtQueryValueKey(is_virtual_handle ? virtual_handle : key_handle, value_name,
		                                           information_class, ptr_out_key_value_information, length,
		                                           ptr_out_result_length);
		const auto is_success = NT_SUCCESS(return_status);

		auto is_unnamed = false;
		const auto handle_name = utils::get_name_from_handle(is_virtual_handle ? virtual_handle : key_handle,
		                                                     is_unnamed);
		//if (!is_success) 
		//	dr_printf("x: %ls\\%ls\nstatus: 0x%lx\n", handle_name.c_str(), value_name->Buffer, return_status);

		if (is_success && (ptr_out_key_value_information != nullptr))
		{
			if (information_class == KeyValueBasicInformation)
			{
				auto ptr_basic_information = static_cast<PKEY_VALUE_BASIC_INFORMATION>(ptr_out_key_value_information);
			}
			else if (information_class == KeyValueFullInformation)
			{
				const auto ptr_full_information = static_cast<PKEY_VALUE_FULL_INFORMATION>(ptr_out_key_value_information
				);
				auto ptr_data = reinterpret_cast<PCHAR>(ptr_full_information) + ptr_full_information->DataOffset;
				if (
					ptr_full_information->Type == REG_SZ ||
					ptr_full_information->Type == REG_MULTI_SZ
				)
				{
					//dr_printf("f: %ls\n", ptr_data);
				}
			}
			else if (information_class == KeyValuePartialInformation)
			{
				auto ptr_partial_information = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(ptr_out_key_value_information
				);
				auto ptr_data = ptr_partial_information->Data;
				if (
					ptr_partial_information->Type == REG_SZ ||
					ptr_partial_information->Type == REG_MULTI_SZ
				)
				{
					//dr_printf("p: %ls\n", ptr_data);
				}
			}
		}


		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtDeleteKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtDeleteKey(
		//		_In_ HANDLE KeyHandle
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle (it's filehandle)

		HKEY virtual_handle{};
		// The key already should be from virtual_reg
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_handle,
		                                                           is_root);

		const auto return_result = NtDeleteKey(is_virtual_handle ? virtual_handle : key_handle);

		//dr_printf("NtDeleteKey: %ls 0x%lx\n", helpers::get_path_from_handle_reg(key_handle).c_str(), key_handle);

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}

		return SYSCALL_SKIP;
	}

	inline bool NtDeleteValueKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtDeleteValueKey(
		//		_In_ HANDLE KeyHandle,
		//		_In_ PUNICODE_STRING ValueName
		//	);

		const auto key_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto value_name_unicode = PUNICODE_STRING(dr_syscall_get_param(drcontext, 1)); // ValueName

		HKEY virtual_handle{};
		// The key already should be from virtual_reg
		auto is_root = false;
		const auto is_virtual_handle = helpers::get_virtual_handle(static_cast<HKEY>(key_handle), virtual_handle,
		                                                           is_root);

		const auto return_status =
			NtDeleteValueKey(is_virtual_handle ? virtual_handle : key_handle, value_name_unicode);

		if (is_virtual_handle)
		{
			RegCloseKey(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateKey(
		//		_Out_ PHANDLE KeyHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Reserved_ ULONG TitleIndex,
		//		_In_opt_ PUNICODE_STRING Class,
		//		_In_ ULONG CreateOptions,
		//		_Out_opt_ PULONG Disposition
		//	);

		const auto ptr_out_key_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		const auto title_index = ULONG(dr_syscall_get_param(drcontext, 3)); // TitleIndex
		const auto reg_class = PUNICODE_STRING(dr_syscall_get_param(drcontext, 4)); // Class
		const auto creation_options = ULONG(dr_syscall_get_param(drcontext, 5)); // CreateOptions
		// Pointer to a variable that receives a value indicating whether a new key was created or an existing one opened.
		const auto ptr_out_disposition = PULONG(dr_syscall_get_param(drcontext, 6)); // Disposition

		if (ptr_object_attributes == nullptr)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		const auto key_path_trace = helpers::get_key_path_trace(ptr_object_attributes);
		const std::string key_path_ascii(key_path_trace.begin(), key_path_trace.end());

#if defined(_WIN64)
		const bool cross_access = desired_access & KEY_WOW64_32KEY;
#else
		const auto cross_access = (desired_access & KEY_WOW64_64KEY) != 0U;
#endif

		bool is_deleted = false;
		auto is_virtual_handle = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::
			get_virtual_object_attributes_reg(ptr_object_attributes, cross_access, is_virtual_handle, trace_string,
			                                  is_deleted);

		const auto return_result = NtCreateKey(ptr_out_key_handle, desired_access,
		                                       is_deleted ? ptr_object_attributes : &virtual_object_attributes,
		                                       title_index, reg_class, creation_options, ptr_out_disposition);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		/// trace call
		json reg_create_key;
		reg_create_key["NtCreateKey"]["before"] = {
			{"key_path", key_path_ascii.c_str()},
		};
		reg_create_key["NtCreateKey"]["success"] = NT_SUCCESS(return_result);
		reg_create_key["NtCreateKey"]["after"] = {
			{"key_handle", (DWORD)*ptr_out_key_handle},
		};
		shared_variables::json_concurrent_vector.push_back(reg_create_key);

		dr_syscall_set_result(drcontext, return_result);
		return SYSCALL_SKIP;
	}

	inline bool open_key_internal(void* drcontext, const PHANDLE ptr_out_key_handle, ACCESS_MASK desired_access,
	                              const POBJECT_ATTRIBUTES ptr_object_attributes, const ULONG open_options,
	                              const bool is_ex = false)
	{
#if defined(_WIN64)
		const auto cross_access = (desired_access & KEY_WOW64_32KEY) != 0U;
#else
		const auto cross_access = (desired_access & KEY_WOW64_64KEY) != 0U;
#endif

		auto is_virtual_handle = false;
		auto is_deleted = false;
		std::wstring trace_string{};
		auto virtual_object_attributes = helpers::
			get_virtual_object_attributes_reg(ptr_object_attributes, cross_access, is_virtual_handle, trace_string,
			                                  is_deleted);

		const auto return_status = NtOpenKeyEx(ptr_out_key_handle, desired_access,
		                                       is_deleted ? ptr_object_attributes : &virtual_object_attributes,
		                                       open_options);
		const auto is_success = NT_SUCCESS(return_status);

		if (is_virtual_handle)
		{
			RegCloseKey(static_cast<HKEY>(virtual_object_attributes.RootDirectory));
		}

		json open_key;
		const std::string key_ascii(trace_string.begin(), trace_string.end());
		// NtOpenKey and NtOpenKeyEx
		const std::string function_name = is_ex ? "NtOpenKeyEx" : "NtOpenKey";
		open_key[function_name]["before"] = {
			{"key_path", key_ascii.c_str()},
		};
		open_key[function_name]["after"] = {
			{"key_handle", reinterpret_cast<DWORD>(*ptr_out_key_handle)},
		};
		open_key[function_name]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(open_key);

		//dr_printf("open: %s\nstatus: 0x%lx\n", key_ascii.c_str(), return_status);

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtOpenKeyEx_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenKeyEx(
		//		_Out_ PHANDLE KeyHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ ULONG OpenOptions
		//	);

		const auto ptr_out_key_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		const auto open_options = ULONG(dr_syscall_get_param(drcontext, 3)); // OpenOptions

		return open_key_internal(drcontext, ptr_out_key_handle, desired_access, ptr_object_attributes, open_options,
		                         true);
	}

	inline bool NtOpenKey_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenKey(
		//		_Out_ PHANDLE KeyHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes
		//	);

		const auto ptr_out_key_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // KeyHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes

		return open_key_internal(drcontext, ptr_out_key_handle, desired_access, ptr_object_attributes,
		                         0);
	}
} // namespace dr_semu::registry::handlers
