#pragma once

#include "includes.h"

#include "filesystem_helpers.hpp"
#include "process_helpers.hpp"

namespace dr_semu::filesystem::handlers
{
	inline bool NtFlushBuffersFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtFlushBuffersFile(
		//		_In_ HANDLE FileHandle,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock
		//	);

		return SYSCALL_CONTINUE;

		const auto file_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // FileHandle
		const auto ptr_out_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 1)); // IoStatusBlock

		if ((file_handle == nullptr) || (ptr_out_io_status_block == nullptr))
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		HANDLE virtual_handle = nullptr;
		auto access_denied = false;
		const auto is_virtual_handle = helpers::get_virtual_handle_fs(file_handle, virtual_handle, access_denied);
		if (access_denied)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtFlushBuffersFile(is_virtual_handle ? virtual_handle : file_handle,
		                                              ptr_out_io_status_block);

		if (is_virtual_handle)
		{
			NtClose(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateSymbolicLinkObject_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateSymbolicLinkObject(
		//		_Out_ PHANDLE LinkHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ PUNICODE_STRING LinkTarget
		//	);

		/******************************************************************************
		 *  NtCreateSymbolicLinkObject	[NTDLL.@]
		 *  ZwCreateSymbolicLinkObject	[NTDLL.@]
		 *
		 * Open a namespace symbolic link object.
		 *
		 * PARAMS
		 *  SymbolicLinkHandle [O] Destination for the new symbolic link handle
		 *  DesiredAccess      [I] Desired access to the symbolic link
		 *  ObjectAttributes   [I] Structure describing the symbolic link
		 *  TargetName         [I] Name of the target symbolic link points to
		 *
		 * RETURNS
		 *  Success: ERROR_SUCCESS.
		 *  Failure: An NTSTATUS error code.
		 */

		const auto ptr_out_link_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // LinkHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		const auto ptr_link_target = PUNICODE_STRING(dr_syscall_get_param(drcontext, 3)); // LinkTarget

		dr_messagebox("[NtCreateSymbolicLinkObject] check parameters and implement the function");

		return SYSCALL_CONTINUE;
	}

	inline bool NtQueryDirectoryFileEx_handler(void* drcontext)
	{
		//NTSTATUS ZwQueryDirectoryFileEx(
		//	_In_     HANDLE                 FileHandle,
		//	_In_opt_ HANDLE                 Event,
		//	_In_opt_ PIO_APC_ROUTINE        ApcRoutine,
		//	_In_opt_ PVOID                  ApcContext,
		//	_Out_    PIO_STATUS_BLOCK       IoStatusBlock,
		//	_Out_    PVOID                  FileInformation,
		//	_In_     ULONG                  Length,
		//	_In_     FILE_INFORMATION_CLASS FileInformationClass,
		//	_In_     ULONG                  QueryFlags,
		//	_In_opt_ PUNICODE_STRING        FileName
		//);

		const auto file_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // FileHandle
		const auto event_handle = HANDLE(dr_syscall_get_param(drcontext, 1)); // Event
		const auto ptr_apc_routine = PIO_APC_ROUTINE(dr_syscall_get_param(drcontext, 2)); // ApcRoutine
		const auto ptr_apc_context = PVOID(dr_syscall_get_param(drcontext, 3)); // ApcContext
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 4)); // IoStatusBlock
		const auto ptr_file_information = PVOID(dr_syscall_get_param(drcontext, 5)); // FileInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 6)); // Length
		const auto file_information_class = FILE_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 7));
		const auto query_flags = ULONG(dr_syscall_get_param(drcontext, 8)); // QueryFlags
		const auto file_name = PUNICODE_STRING(dr_syscall_get_param(drcontext, 9)); // FileName

		HANDLE virtual_handle{};
		auto access_denied = false;
		const auto is_virtual_handle = helpers::get_virtual_handle_fs(file_handle, virtual_handle, access_denied);
		if (access_denied)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		// TODO(win_p): TEMP fix, wait for phnt update
		const auto ZwQueryDirectoryFileEx = reinterpret_cast<ZwQueryDirectoryFileExFunc*>(GetProcAddress(
			LoadLibrary(L"ntdll.dll"), "ZwQueryDirectoryFileEx"));
		const auto return_status = ZwQueryDirectoryFileEx(is_virtual_handle ? virtual_handle : file_handle,
		                                                  event_handle, ptr_apc_routine, ptr_apc_context,
		                                                  ptr_io_status_block,
		                                                  ptr_file_information, length, file_information_class,
		                                                  query_flags, file_name);

		if (is_virtual_handle)
		{
			NtClose(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}


	inline bool NtQueryDirectoryFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//NTSTATUS
		//NTAPI
		//NtQueryDirectoryFile(
		//	_In_ HANDLE FileHandle,
		//	_In_opt_ HANDLE Event,
		//	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		//	_In_opt_ PVOID ApcContext,
		//	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//	_Out_writes_bytes_(Length) PVOID FileInformation,
		//	_In_ ULONG Length,
		//	_In_ FILE_INFORMATION_CLASS FileInformationClass,
		//	_In_ BOOLEAN ReturnSingleEntry,
		//	_In_opt_ PUNICODE_STRING FileName,
		//	_In_ BOOLEAN RestartScan
		//);

		const auto file_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // FileHandle
		const auto event_handle = HANDLE(dr_syscall_get_param(drcontext, 1)); // Event
		const auto ptr_apc_routine = PIO_APC_ROUTINE(dr_syscall_get_param(drcontext, 2)); // ApcRoutine
		const auto ptr_apc_context = PVOID(dr_syscall_get_param(drcontext, 3)); // ApcContext
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 4)); // IoStatusBlock
		const auto ptr_file_information = PVOID(dr_syscall_get_param(drcontext, 5)); // FileInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 6)); // Length
		const auto file_information_class = FILE_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 7));
		// FileInformationClass
		const auto return_single_entry = BOOLEAN(dr_syscall_get_param(drcontext, 8)); // ReturnSingleEntry
		const auto file_name = PUNICODE_STRING(dr_syscall_get_param(drcontext, 9)); // FileName
		const auto restart_scan = BOOLEAN(dr_syscall_get_param(drcontext, 10)); // RestartScan

		HANDLE virtual_handle{};
		auto access_denied = false;
		const auto is_virtual_handle = helpers::get_virtual_handle_fs(file_handle, virtual_handle, access_denied);
		if (access_denied)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtQueryDirectoryFile(is_virtual_handle ? virtual_handle : file_handle, event_handle,
		                                                ptr_apc_routine, ptr_apc_context, ptr_io_status_block,
		                                                ptr_file_information, length, file_information_class,
		                                                return_single_entry, file_name, restart_scan);

		//if (file_information_class == FileIdBothDirectoryInformation)
		//{
		//	const auto dir_info = static_cast<PFILE_ID_BOTH_DIR_INFORMATION>(ptr_file_information);
		//}

		const auto original_path = helpers::get_original_full_path(file_handle, L"");

		//dr_printf("ret: 0x%lx\n", return_status);

		if (is_virtual_handle)
		{
			NtClose(virtual_handle);
		}
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtQueryFullAttributesFile_handler(void* drcontext)
	{
		//	NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryFullAttributesFile(
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Out_ PFILE_NETWORK_OPEN_INFORMATION FileInformation
		//	);

		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0));
		const auto ptr_file_network_open_information = PFILE_NETWORK_OPEN_INFORMATION(
			dr_syscall_get_param(drcontext, 1));

		if (nullptr == ptr_object_attributes)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		OBJECT_ATTRIBUTES virtual_object_attributes{};
		auto is_virtual_handle = false;
		auto is_new_unicode = false;
		const auto is_virtual_attributes = helpers::get_virtual_object_attributes_fs(
			ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);
		if (!is_virtual_attributes)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtQueryFullAttributesFile(&virtual_object_attributes,
		                                                     ptr_file_network_open_information);
		const auto is_success = NT_SUCCESS(return_status);

		/// trace call
		auto full_path = helpers::get_original_full_path(virtual_object_attributes.RootDirectory,
		                                                 virtual_object_attributes.ObjectName);
		full_path = helpers::normalize_path(full_path);

		json query_file_attr;
		const std::string full_path_ascii(full_path.begin(), full_path.end());
		query_file_attr["NtQueryFullAttributesFile"]["before"] = {
			{"file_path", full_path_ascii.c_str()},
		};
		query_file_attr["NtQueryFullAttributesFile"]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(query_file_attr);


		if (is_virtual_handle && (virtual_object_attributes.RootDirectory != nullptr))
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}
		if (is_new_unicode)
		{
			delete virtual_object_attributes.ObjectName;
		}
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateIoCompletion_handler(void* drcontext)
	{
		//	NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateIoCompletion(
		//		_Out_ PHANDLE IoCompletionHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_opt_ ULONG Count
		//	);

		const auto ptr_handle = PHANDLE(dr_syscall_get_param(drcontext, 0));
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		const auto count = ULONG(dr_syscall_get_param(drcontext, 3));

		if (ptr_object_attributes != nullptr)
		{
			OBJECT_ATTRIBUTES virtual_object_attributes{};
			auto is_virtual_handle = false;
			auto is_new_unicode = false;
			const auto is_obj_attr = helpers::get_virtual_object_attributes_fs(
				ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);
			if (!is_obj_attr)
			{
				dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
				return SYSCALL_SKIP;
			}

			const auto return_status = NtCreateIoCompletion(ptr_handle, desired_access, &virtual_object_attributes,
			                                                count);

			if (is_virtual_handle && (virtual_object_attributes.RootDirectory != nullptr))
			{
				NtClose(virtual_object_attributes.RootDirectory);
			}
			if (is_new_unicode)
			{
				delete virtual_object_attributes.ObjectName;
			}

			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_SKIP;
		}

		return SYSCALL_CONTINUE;
	}

	/* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/mm/modwrite/create.htm */
	// "The ordinary caller of the function is SMSS.EXE, i.e., the Session Manager, which creates paging files (including, nowadays, working set swap paging files) as Windows starts."
	inline bool NtCreatePagingFile_handler(void* drcontext)
	{
		dr_syscall_set_result(drcontext, STATUS_PRIVILEGE_NOT_HELD);
		return SYSCALL_SKIP;
	}

	/* The NtCreateDirectoryObject routine creates or opens a directory object. */
	inline bool NtCreateDirectoryObject_hook(void* drcontext)
	{
		//	NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateDirectoryObject(
		//		_Out_ PHANDLE DirectoryHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes
		//	);

		const auto ptr_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // DirectoryHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));

		if (ptr_object_attributes == nullptr || ptr_object_attributes->ObjectName == nullptr)
		{
			*ptr_handle = nullptr;
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		OBJECT_ATTRIBUTES virtual_object_attributes{};
		auto is_virtual_handle = false;
		auto is_new_unicode = false;
		const auto is_valid = helpers::get_virtual_object_attributes_fs(
			ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);
		if (!is_valid)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtCreateDirectoryObject(ptr_handle, desired_access, &virtual_object_attributes);

		if (is_virtual_handle && (virtual_object_attributes.RootDirectory != nullptr))
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}
		if (is_new_unicode)
		{
			delete virtual_object_attributes.ObjectName;
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtDeleteFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtDeleteFile(
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes
		//	);

		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0));

		OBJECT_ATTRIBUTES virtual_object_attributes;
		auto is_virtual_handle = false;
		auto is_new_unicode = false;
		const auto is_virtual_attributes = helpers::get_virtual_object_attributes_fs(
			ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);
		if (!is_virtual_attributes)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtDeleteFile(&virtual_object_attributes);

		if (is_virtual_handle)
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}
		if (is_new_unicode)
		{
			delete virtual_object_attributes.ObjectName;
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtQueryAttributesFile_hook(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryAttributesFile(
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Out_ PFILE_BASIC_INFORMATION FileInformation
		//	);

		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 0));
		const auto ptr_file_information = PFILE_BASIC_INFORMATION(dr_syscall_get_param(drcontext, 1));


		if (ptr_object_attributes == nullptr || ptr_object_attributes->ObjectName == nullptr)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		OBJECT_ATTRIBUTES virtual_object_attributes{};
		auto is_virtual_handle = false;
		auto is_new_unicode = false;
		const auto is_valid = helpers::get_virtual_object_attributes_fs(
			ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);

		if (!is_valid)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtQueryAttributesFile(&virtual_object_attributes, ptr_file_information);

		if (is_virtual_handle && (virtual_object_attributes.RootDirectory != nullptr))
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}
		if (is_new_unicode)
		{
			delete virtual_object_attributes.ObjectName;
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtSetInformationFile_hook(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSetInformationFile(
		//		_In_ HANDLE FileHandle,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_reads_bytes_(Length) PVOID FileInformation,
		//		_In_ ULONG Length,
		//		_In_ FILE_INFORMATION_CLASS FileInformationClass
		//	);

		const auto handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 1));
		const auto ptr_file_information = PVOID(dr_syscall_get_param(drcontext, 2));
		auto length = ULONG(dr_syscall_get_param(drcontext, 3));
		const auto file_information_class = FILE_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 4));

		const auto tid = dr_get_thread_id(drcontext);

		HANDLE virtual_handle{};
		auto access_denied = false;
		const auto is_virtual_handle_allocated = helpers::get_virtual_handle_fs(handle, virtual_handle, access_denied);
		if (access_denied)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		bool is_unnamed{};
		const auto path = utils::get_name_from_handle(handle, is_unnamed);
		const auto v_path = utils::get_name_from_handle(virtual_handle, is_unnamed);

		if (file_information_class == FileRenameInformation ||
			file_information_class == FileRenameInformationEx ||
			file_information_class == FileRenameInformationBypassAccessCheck /* Kernel-Only */ ||
			file_information_class == FileRenameInformationExBypassAccessCheck
		)
		{
			const auto ptr_file_rename_information = static_cast<PFILE_RENAME_INFORMATION>(ptr_file_information);
			// FileNameLength : Length, in bytes, of the new name for the file.
			const std::wstring target_path(ptr_file_rename_information->FileName,
			                               ptr_file_rename_information->FileNameLength / sizeof(WCHAR));
			auto target_virtual_path{target_path}; // new name


			auto path_size_in_bytes = ptr_file_rename_information->FileNameLength;
			HANDLE virtual_file_rename_handle = nullptr;
			auto is_virtual_rename_handle_allocated = false;
			if (ptr_file_rename_information->RootDirectory != nullptr)
			{
				is_virtual_rename_handle_allocated = helpers::get_virtual_handle_fs(
					ptr_file_rename_information->RootDirectory, virtual_file_rename_handle, access_denied);
				if (access_denied)
				{
					dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
					return SYSCALL_SKIP;
				}
			}
			else
			{
				// target_path specifies full path
				const auto is_valid = helpers::original_path_to_virtual_fs(target_path, target_virtual_path);
				if (!is_valid)
				{
					dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
					return SYSCALL_SKIP;
				}
				path_size_in_bytes = target_virtual_path.length() * sizeof(WCHAR);
				length = path_size_in_bytes + sizeof(FILE_RENAME_INFORMATION);
			}

			const auto ptr_new_rename_information = PFILE_RENAME_INFORMATION(new BYTE[length]);
			ptr_new_rename_information->ReplaceIfExists = ptr_file_rename_information->ReplaceIfExists;
			ptr_new_rename_information->RootDirectory = is_virtual_rename_handle_allocated
				                                            ? virtual_file_rename_handle
				                                            : ptr_file_rename_information->RootDirectory;
			ptr_new_rename_information->FileNameLength = path_size_in_bytes;

			memcpy_s(ptr_new_rename_information->FileName, path_size_in_bytes, target_virtual_path.c_str(),
			         target_virtual_path.length() * sizeof(WCHAR));

			auto is_whitelisted = false;
			const auto old_path_virtual = helpers::get_path_from_handle(handle, is_whitelisted);
			const auto old_path = helpers::normalize_path(helpers::virtual_to_original_fs(old_path_virtual));

			//dr_printf("trg_vrt [%d]: %ls\n", tid, target_virtual_path.c_str());
			const auto new_path = helpers::normalize_path(
				helpers::get_original_full_path(ptr_new_rename_information->RootDirectory, target_virtual_path));

			const auto return_status = NtSetInformationFile(is_virtual_handle_allocated ? virtual_handle : handle,
			                                                ptr_io_status_block, ptr_new_rename_information, length,
			                                                file_information_class);
			delete[] ptr_new_rename_information;
			const auto is_success = NT_SUCCESS(return_status);

			/// trace call
			json rename_file;
			const std::string old_path_ascii(old_path.begin(), old_path.end());
			const std::string new_path_ascii(new_path.begin(), new_path.end());
			rename_file["NtSetInformationFile"]["FileRename"] = {
				{"old_path", old_path_ascii.c_str()},
				{"new_path", new_path_ascii.c_str()},
			};
			rename_file["NtSetInformationFile"]["FileRename"]["success"] = is_success;
			shared_variables::json_concurrent_vector.push_back(rename_file);

			if (is_virtual_handle_allocated)
			{
				NtClose(virtual_handle);
			}
			if (is_virtual_rename_handle_allocated)
			{
				NtClose(virtual_file_rename_handle);
			}
			dr_syscall_set_result(drcontext, return_status);
			return SYSCALL_SKIP;
		}

		const auto return_status = NtSetInformationFile(
			is_virtual_handle_allocated ? virtual_handle : handle,
			ptr_io_status_block,
			ptr_file_information,
			length,
			file_information_class);

		if (is_virtual_handle_allocated)
		{
			NtClose(virtual_handle);
		}
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtQueryInformationFile_hook(void* drcontext)
	{
		//	NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryInformationFile(
		//		_In_ HANDLE FileHandle,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_Out_writes_bytes_(Length) PVOID FileInformation,
		//		_In_ ULONG Length,
		//		_In_ FILE_INFORMATION_CLASS FileInformationClass
		//	);

		const auto handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // FileHandle
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 1)); // IoStatusBlock
		const auto ptr_file_information = PVOID(dr_syscall_get_param(drcontext, 2)); // FileInformation
		const auto length = ULONG(dr_syscall_get_param(drcontext, 3)); // Length
		const auto file_information_class = FILE_INFORMATION_CLASS(dr_syscall_get_param(drcontext, 4));
		// FileInformationClass

		HANDLE virtual_handle{};
		auto access_denied = false;
		const auto is_virtual_handle = helpers::get_virtual_handle_fs(handle, virtual_handle, access_denied);
		if (access_denied)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		bool whitelisted;
		const auto file_path = helpers::get_path_from_handle(handle, whitelisted);
		const std::string file_path_ascii(file_path.begin(), file_path.end());

		dr_printf("[Dr.Semu] file_path: %ls\n%d\n", file_path.c_str(), file_information_class);
		
		const auto return_status = NtQueryInformationFile(is_virtual_handle ? virtual_handle : handle,
		                                                  ptr_io_status_block, ptr_file_information, length,
		                                                  file_information_class);
		const auto is_success = NT_SUCCESS(return_status);
		
		json query_file_info;
		query_file_info["NtQueryInformationFile"]["before"] = {
			{"handle", reinterpret_cast<DWORD>(handle)},
			{"information_class", file_information_class},
			{"file_path", file_path_ascii},
		};
		query_file_info["NtQueryInformationFile"]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(query_file_info);

		// TODO (lasha): redirect data from FileStandardInformation
		if (is_success)
		{
			if (file_information_class == FileNameInformation)
			{
				const auto ptr_name_information = (PFILE_NAME_INFORMATION)ptr_file_information;
				// FileName: The name string is not null-terminated.
				// FileNameLength: unsigned integer that specifies the length, in bytes, of the file name contained within the FileName field.
				dr_printf("info: %ls\n", ptr_name_information->FileName);
				// filename looks like:  \Users\XXX\AppData (without c:)
			}
		}
		
		if (is_virtual_handle)
		{
			NtClose(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtMapViewOfSection_hook(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtMapViewOfSection(
		//		_In_ HANDLE SectionHandle,
		//		_In_ HANDLE ProcessHandle,
		//		_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
		//		_In_ ULONG_PTR ZeroBits,
		//		_In_ SIZE_T CommitSize,
		//		_Inout_opt_ PLARGE_INTEGER SectionOffset,
		//		_Inout_ PSIZE_T ViewSize,
		//		_In_ SECTION_INHERIT InheritDisposition,
		//		_In_ ULONG AllocationType,
		//		_In_ ULONG Win32Protect
		//	);

		const auto section_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // SectionHandle
		const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 1)); // ProcessHandle

		//dr_printf("section: 0x%x process:: 0x%lx\n", section_handle, process_handle);
		//dr_messagebox("X");

		return SYSCALL_CONTINUE;
	}

	inline bool NtCreateSection_handler(void* drcontext)
	{
		//	NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateSection(
		//		_Out_ PHANDLE SectionHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_opt_ PLARGE_INTEGER MaximumSize,
		//		_In_ ULONG SectionPageProtection,
		//		_In_ ULONG AllocationAttributes,
		//		_In_opt_ HANDLE FileHandle
		//	);

		// Function NtCreateSection creates Section Object (virtual memory block with associated file).

		const auto section_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // SectionHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		const auto maximum_size = PLARGE_INTEGER(dr_syscall_get_param(drcontext, 3)); // MaximumSize
		const auto section_page_protection = ULONG(dr_syscall_get_param(drcontext, 4)); // SectionPageProtection
		const auto allocation_attributes = ULONG(dr_syscall_get_param(drcontext, 5)); // AllocationAttributes
		const auto file_handle = HANDLE(dr_syscall_get_param(drcontext, 6)); // FileHandle

		auto is_virtual_handle_attr = false;
		auto is_virtual_attr_valid = false;
		auto is_new_unicode_attr = false;
		OBJECT_ATTRIBUTES virtual_object_attributes{};
		if (ptr_object_attributes != nullptr)
		{
			is_virtual_attr_valid = helpers::get_virtual_object_attributes_fs(
				ptr_object_attributes, &virtual_object_attributes, is_virtual_handle_attr, is_new_unicode_attr);
			if (!is_virtual_attr_valid)
			{
				dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
				return SYSCALL_SKIP;
			}
		}

		auto is_virtual_handle = false;
		HANDLE virtual_handle = nullptr;

		if ((file_handle != nullptr) && helpers::is_handle_file_or_dir(file_handle))
		{
			auto access_denied = false;
			is_virtual_handle = helpers::get_virtual_handle_fs(file_handle, virtual_handle, access_denied);
			if (access_denied)
			{
				dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
				return SYSCALL_SKIP;
			}
		}

		const auto return_status = NtCreateSection(section_handle, desired_access,
		                                           is_virtual_attr_valid
			                                           ? &virtual_object_attributes
			                                           : ptr_object_attributes, maximum_size, section_page_protection,
		                                           allocation_attributes,
		                                           is_virtual_handle ? virtual_handle : file_handle);
		const auto is_success = NT_SUCCESS(return_status);

		if (is_virtual_handle_attr && (virtual_object_attributes.RootDirectory != nullptr))
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}
		if (is_virtual_handle)
		{
			NtClose(virtual_handle);
		}
		if (is_new_unicode_attr)
		{
			delete virtual_object_attributes.ObjectName;
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtOpenFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenFile(
		//		_Out_ PHANDLE FileHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_ ULONG ShareAccess,
		//		_In_ ULONG OpenOptions
		//	);

		const auto ptr_out_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // FileHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		// ObjectAttributes
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 3)); // IoStatusBlock
		const auto share_access = ULONG(dr_syscall_get_param(drcontext, 4)); // ShareAccess
		const auto open_options = ULONG(dr_syscall_get_param(drcontext, 5)); // OpenOptions

		if (ptr_out_handle == nullptr)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}
		if (ptr_object_attributes == nullptr || ptr_object_attributes->ObjectName == nullptr)
		{
			*ptr_out_handle = nullptr;
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		const auto file_path_original = helpers::get_full_path(ptr_object_attributes);
		if (file_path_original.find(LR"(\dr_semu_)") != std::wstring::npos)
		{
			*ptr_out_handle = nullptr;
			//xxx;
			// TODO (lasha): redirect data from NtQueryInformationFile
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}
		
		OBJECT_ATTRIBUTES virtual_object_attributes{};
		auto is_virtual_handle = false;
		auto is_new_unicode = false;
		const auto is_valid = helpers::get_virtual_object_attributes_fs(
			ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);

		if (!is_valid)
		{
			dr_printf("[NtOpenFile] denied: root_handle: 0x%lx obj_name: %ls\n", ptr_object_attributes->RootDirectory,
			          ptr_object_attributes->ObjectName->Buffer);
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		/// trace syscall
		std::string full_path_ascii{};
		const auto full_path_wide = helpers::get_original_full_path(virtual_object_attributes.RootDirectory,
		                                                            virtual_object_attributes.ObjectName);
		full_path_ascii = std::string(full_path_wide.begin(), full_path_wide.end());


		const auto return_status = NtOpenFile(ptr_out_handle, desired_access, &virtual_object_attributes,
		                                      ptr_io_status_block, share_access, open_options);
		const auto is_success = NT_SUCCESS(return_status);
		
		if (is_virtual_handle && (virtual_object_attributes.RootDirectory != nullptr))
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}
		if (is_new_unicode)
		{
			delete virtual_object_attributes.ObjectName;
		}

		json open_file_json;
		open_file_json["NtOpenFile"]["before"] = {
			{"path", full_path_ascii.c_str()},
			{"desired_access", desired_access},
			{"object_name", full_path_ascii.c_str()},
			{"share_access", share_access}
		};
		open_file_json["NtOpenFile"]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(open_file_json);
		
		//dr_printf("name: %ls\nbefore: %ls\nroot: 0x%lx\nret: 0x%x\n", object_name_wide.c_str(), virtual_object_attributes.ObjectName->Buffer, virtual_object_attributes.RootDirectory, return_status);

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateFile(
		//		_Out_ PHANDLE FileHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_opt_ PLARGE_INTEGER AllocationSize,
		//		_In_ ULONG FileAttributes,
		//		_In_ ULONG ShareAccess,
		//		_In_ ULONG CreateDisposition,
		//		_In_ ULONG CreateOptions,
		//		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		//		_In_ ULONG EaLength
		//	);


		const auto ptr_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // FileHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2));
		// ObjectAttributes
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 3)); // IoStatusBlock
		const auto ptr_allocation_size = PLARGE_INTEGER(dr_syscall_get_param(drcontext, 4)); // AllocationSize
		const auto file_attributes = ULONG(dr_syscall_get_param(drcontext, 5)); // FileAttributes
		const auto share_access = ULONG(dr_syscall_get_param(drcontext, 6)); // ShareAccess
		const auto create_disposition = ULONG(dr_syscall_get_param(drcontext, 7)); // CreateDisposition
		const auto create_options = ULONG(dr_syscall_get_param(drcontext, 8)); // CreateOptions
		const auto ea_buffer = PVOID(dr_syscall_get_param(drcontext, 9)); // EaBuffer
		const auto ea_length = ULONG(dr_syscall_get_param(drcontext, 10)); // EaLength

		if (ptr_object_attributes == nullptr || ptr_object_attributes->ObjectName == nullptr)
		{
			*ptr_handle = nullptr;
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}
		
		const auto file_path_original = helpers::get_full_path(ptr_object_attributes);
		if (file_path_original.find(LR"(\dr_semu_)") != std::wstring::npos)
		{
			*ptr_handle = nullptr;
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}
		

		const auto tid = dr_get_thread_id(drcontext);

		OBJECT_ATTRIBUTES virtual_object_attributes{};
		auto is_new_unicode = false;
		auto is_virtual_handle = false;
		const auto continue_execution = helpers::get_virtual_object_attributes_fs(
			ptr_object_attributes, &virtual_object_attributes, is_virtual_handle, is_new_unicode);

		if (!continue_execution)
		{
			dr_printf("[NtCreateFile] denied: root_handle: 0x%lx obj_name: %ls\n", ptr_object_attributes->RootDirectory,
			          ptr_object_attributes->ObjectName->Buffer);
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		const auto virtual_path = helpers::get_full_path(virtual_object_attributes.RootDirectory,
		                                                 virtual_object_attributes.ObjectName->Buffer);
		if (utils::find_case_insensitive(virtual_path, LR"(C:\)") != std::wstring::npos &&
			utils::find_case_insensitive(
				virtual_path, shared_variables::virtual_filesystem_location) == std::wstring::npos)
		{
			dr_printf("[NtCreateFile] [%d] failed to get a virtual path: %ls\n", tid, virtual_path.c_str());
			dr_messagebox("failed to get a virtual path");
		}

		/*
		ISSUE: ping.exe (and other executables) fails if there is no .mui files
		"C:\Windows\SysWOW64\en\PING.EXE.mui"
		under Procmon Ping.exe (without dr.semu) also checks system32 if there is no the .mui file under syswow64
		SOLUTION: if operation is OPEN_EXISTING and a target path contains SysWOw64 and ends with .mui
		and there is such file => change syswow64 with system32
		C:\Windows\system32\en\PING.EXE.mui
		*/
		// TODO (lasha): Similar problem with notepad.exe but the solution can not solve the issue with notepad.exe
		// PROBLEM: our client is injected after looking for .mui files (is early injection possible solution?)
		// Is the problem serious? I don't think so, not many executables use .mui files especially malware
		if (create_disposition == FILE_OPEN &&
			virtual_path.ends_with(L".mui") &&
			utils::find_case_insensitive(virtual_path, LR"(syswow64)") != std::wstring::npos &&
			!fs::exists(virtual_path)
		)
		{
			// TODO (lasha): change syswow64 to system32 (syswow64_to_system32(wstr))
			//dr_printf("path: %ls\ncd: 0x%x", virtual_path.c_str(), create_disposition);
		}

		const auto return_status = NtCreateFile(ptr_handle, desired_access, &virtual_object_attributes,
		                                        ptr_io_status_block,
		                                        ptr_allocation_size, file_attributes, share_access, create_disposition,
		                                        create_options, ea_buffer, ea_length);
		if (is_new_unicode)
		{
			delete virtual_object_attributes.ObjectName;
		}
		const auto is_success = NT_SUCCESS(return_status);

		/// trace syscall
		const auto file_full_path = helpers::normalize_path(
			helpers::get_original_full_path(ptr_object_attributes->RootDirectory,
			                                virtual_object_attributes.ObjectName));

		const std::string file_full_path_ascii(file_full_path.begin(), file_full_path.end());
		const auto is_valid_path = !file_full_path_ascii.empty();

		json create_file_json;
		create_file_json["NtCreateFile"]["before"] = {
			{"desired_access", desired_access},
			{"file_path", is_valid_path ? file_full_path_ascii : "<EMPTY>"},
			{"file_attributes", file_attributes},
			{"create_disposition", create_disposition},
			{"create_options", create_options},
			{"share_access", share_access}
		};
		create_file_json["NtCreateFile"]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(create_file_json);


		if (is_virtual_handle && (virtual_object_attributes.RootDirectory != nullptr))
		{
			NtClose(virtual_object_attributes.RootDirectory);
		}


		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtWriteFile_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtWriteFile(
		//		_In_ HANDLE FileHandle,
		//		_In_opt_ HANDLE Event,
		//		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		//		_In_opt_ PVOID ApcContext,
		//		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		//		_In_reads_bytes_(Length) PVOID Buffer,
		//		_In_ ULONG Length,
		//		_In_opt_ PLARGE_INTEGER ByteOffset,
		//		_In_opt_ PULONG Key
		//	);

		const auto handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // Handle
		const auto event_handle = HANDLE(dr_syscall_get_param(drcontext, 1)); // Event
		const auto ptr_apc_routine = PIO_APC_ROUTINE(dr_syscall_get_param(drcontext, 2)); // ApcRoutine
		const auto ptr_apc_context = PVOID(dr_syscall_get_param(drcontext, 3)); // ApcContext
		const auto ptr_io_status_block = PIO_STATUS_BLOCK(dr_syscall_get_param(drcontext, 4)); // IoStatusBlock
		const auto ptr_buffer = PVOID(dr_syscall_get_param(drcontext, 5)); // Buffer
		const auto length = ULONG(dr_syscall_get_param(drcontext, 6)); // Length
		const auto ptr_byte_offset = PLARGE_INTEGER(dr_syscall_get_param(drcontext, 7)); // ByteOffset
		const auto ptr_key = PULONG(dr_syscall_get_param(drcontext, 8)); // Key

		HANDLE virtual_handle{};
		auto access_denied = false;
		const auto is_virtual_handle = helpers::get_virtual_handle_fs(handle, virtual_handle, access_denied);
		if (access_denied)
		{
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}
		const auto current_handle = is_virtual_handle ? virtual_handle : handle;

		const auto return_status = NtWriteFile(current_handle, event_handle,
		                                       ptr_apc_routine, ptr_apc_context, ptr_io_status_block, ptr_buffer,
		                                       length, ptr_byte_offset, ptr_key);
		const auto is_success = NT_SUCCESS(return_status);

		/// trace call
		const auto full_path = helpers::normalize_path(helpers::get_original_full_path(current_handle, nullptr));
		const std::string full_path_ascii(full_path.begin(), full_path.end());

		json write_file;
		write_file["NtWriteFile"]["before"] = {
			{"path", full_path_ascii.c_str()},
		};
		write_file["NtWriteFile"]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(write_file);

		if (is_virtual_handle)
		{
			NtClose(virtual_handle);
		}

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtClose_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtClose(
		//		_In_ HANDLE Handle
		//	);

		const auto handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // Handle

		// no need to check

		return SYSCALL_CONTINUE;
	}
} // namespace dr_semu::filesystem::handlers
