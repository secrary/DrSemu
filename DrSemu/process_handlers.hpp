#pragma once

#include "includes.h"
#include "process_helpers.hpp"
#include "static_details.hpp"

namespace dr_semu::process::handlers
{
	inline bool NtSetContextThread_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSetContextThread(
		//		_In_ HANDLE ThreadHandle,
		//		_In_ PCONTEXT ThreadContext
		//	);

		//const auto thread_handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		//const auto ptr_thread_context = PCONTEXT(dr_syscall_get_param(drcontext, 1));

		//if (ptr_thread_context != nullptr)
		//{
		//	dr_printf("[NtSetContextThread] EIP: 0x%lx\n", ptr_thread_context->Eip);
		//}

		return SYSCALL_CONTINUE;
	}

	inline bool NtProtectVirtualMemory_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtProtectVirtualMemory(
		//		_In_ HANDLE ProcessHandle,
		//		_Inout_ PVOID * BaseAddress,
		//		_Inout_ PSIZE_T RegionSize,
		//		_In_ ULONG NewProtect,
		//		_Out_ PULONG OldProtect
		//	);

		const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		const auto ptr_base_address = reinterpret_cast<PVOID*>(dr_syscall_get_param(drcontext, 1));
		const auto ptr_region_size = PSIZE_T(dr_syscall_get_param(drcontext, 2));
		const auto new_protect = ULONG(dr_syscall_get_param(drcontext, 3));
		const auto ptr_out_old_protect = PULONG(dr_syscall_get_param(drcontext, 4));

		//	0x01 - PAGE_NOACCESS
		//	0x02 - PAGE_READONLY
		//	0x04 - PAGE_READWRITE
		//	0x08 - PAGE_WRITECOPY
		//	0x10 - PAGE_EXECUTE
		//	0x20 - PAGE_EXECUTE_READ
		//	0x40 - PAGE_EXECUTE_READWRITE
		//	0x80 - PAGE_EXECUTE_WRITECOPY
		//Modifiers :
		//	0x100 - PAGE_GUARD
		//	0x200 - PAGE_NOCACHE
		//	0x400 - PAGE_WRITECOMBINE


		const auto return_status = NtProtectVirtualMemory(process_handle, ptr_base_address, ptr_region_size,
		                                                  new_protect, ptr_out_old_protect);
		const auto is_success = NT_SUCCESS(return_status);

		json virtual_protect;
		virtual_protect["NtProtectVirtualMemory"]["before"] = {
			{"process_handle", reinterpret_cast<ULONG>(process_handle)},
			{"base_address", reinterpret_cast<DWORD_PTR>(*ptr_base_address)},
			{"new_protect", new_protect},
		};
		virtual_protect["NtProtectVirtualMemory"]["success"] = is_success;
		shared_variables::json_concurrent_vector.push_back(virtual_protect);

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtContinue_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtContinue(
		//		_In_ PCONTEXT ContextRecord,
		//		_In_ BOOLEAN TestAlert
		//	);

//		const auto ptr_context_record = PCONTEXT(dr_syscall_get_param(drcontext, 0));
//		//const auto test_alert = BOOLEAN(dr_syscall_get_param(drcontext, 1));
//
//		if (ptr_context_record != nullptr)
//		{
//#ifdef _WIN64
//		const auto ip = ptr_context_record->Rip;
//#else
//			const auto ip = ptr_context_record->Eip;
//#endif // WIN32
//
//			//dr_printf("[NtContinue] EIP: 0x%lx\n", ip);
//		}

		return SYSCALL_CONTINUE;
	}

	inline bool NtSetInformationProcess_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSetInformationProcess(
		//		_In_ HANDLE ProcessHandle,
		//		_In_ PROCESSINFOCLASS ProcessInformationClass,
		//		_In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
		//		_In_ ULONG ProcessInformationLength
		//	);

		//const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		//const auto process_info_class = PROCESSINFOCLASS(dr_syscall_get_param(drcontext, 1));
		//const auto ptr_process_information = PVOID(dr_syscall_get_param(drcontext, 2));
		//const auto process_info_length = ULONG(dr_syscall_get_param(drcontext, 3));

		//if (process_info_class == ProcessDefaultHardErrorMode)
		//{
		//	const auto ptr_error_mode = static_cast<PULONG>(ptr_process_information);
		//	//dr_printf("[ProcessDefaultHardErrorMode] error_mode: 0x%x\n", *ptr_error_mode);
		//}

		return SYSCALL_CONTINUE;
	}

	inline bool NtQueryInformationProcess_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryInformationProcess(
		//		_In_ HANDLE ProcessHandle,
		//		_In_ PROCESSINFOCLASS ProcessInformationClass,
		//		_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
		//		_In_ ULONG ProcessInformationLength,
		//		_Out_opt_ PULONG ReturnLength
		//	);


		const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		const auto process_info_class = PROCESSINFOCLASS(dr_syscall_get_param(drcontext, 1));
		const auto ptr_out_process_information = PVOID(dr_syscall_get_param(drcontext, 2));
		const auto process_info_length = ULONG(dr_syscall_get_param(drcontext, 3));
		const auto ptr_out_return_length = PULONG(dr_syscall_get_param(drcontext, 4));

		const auto tid = dr_get_thread_id(drcontext);

		const auto return_status = NtQueryInformationProcess(process_handle, process_info_class,
		                                                     ptr_out_process_information, process_info_length,
		                                                     ptr_out_return_length);
		const auto is_success = NT_SUCCESS(return_status);

		const auto handle_name = helpers::get_process_name(process_handle);
		const auto process_name = handle_name.empty() ? L"<NULL>" : handle_name;
		const std::string process_name_ascii(process_name.begin(), process_name.end());
		std::string information_class_trace = "UNKNOWN";

		// TODO (lasha): filter more classes
		if (process_info_class == ProcessWow64Information)
		{
			information_class_trace = "ProcessWow64Information";
		}
		if (process_info_class == ProcessMitigationPolicy)
		{
			information_class_trace = "ProcessMitigationPolicy";
		}
		if (process_info_class == ProcessIoCounters)
		{
			information_class_trace = "ProcessIoCounters";
		}
		if (process_info_class == ProcessBasicInformation)
		{
			information_class_trace = "ProcessBasicInformation";
		}
		if (process_info_class == ProcessWindowInformation)
		{
			information_class_trace = "ProcessWindowInformation";
		}
		if (process_info_class == ProcessPriorityBoost)
		{
			information_class_trace = "ProcessPriorityBoost";
		}
		if (process_info_class == ProcessDefaultHardErrorMode)
		{
			information_class_trace = "ProcessDefaultHardErrorMode";

			//#define SEM_FAILCRITICALERRORS      0x0001
			//#define SEM_NOGPFAULTERRORBOX       0x0002
			//#define SEM_NOALIGNMENTFAULTEXCEPT  0x0004
			//#define SEM_NOOPENFILEERRORBOX      0x8000
			
			//const auto ptr_error_mode = static_cast<PULONG>(ptr_out_process_information);
			//dr_printf("error_mode: 0x%lx\n", *ptr_error_mode);
		}

		if (process_info_class == ProcessImageInformation)
		{
			information_class_trace = "ProcessImageInformation";
		}
		if (process_info_class == ProcessDeviceMap)
		{
			information_class_trace = "ProcessDeviceMap";
		}
		if (process_info_class == ProcessDebugPort)
		{
			information_class_trace = "ProcessDebugPort";
		}
		if (process_info_class == ProcessImageFileName)
		{
			information_class_trace = "ProcessImageFileName";
		}
		if (process_info_class == ProcessImageFileNameWin32)
		{
			information_class_trace = "ProcessImageFileNameWin32";
		}
		if (is_success &&
			(process_info_class == ProcessImageFileNameWin32 || process_info_class == ProcessImageFileName)
		)
		{
			const auto ptr_unicode = static_cast<PUNICODE_STRING>(ptr_out_process_information);

			// hide fake explorer path
			std::wstring image_path{};
			if (utils::unicode_string_to_wstring(ptr_unicode, image_path))
			{
				if (image_path.find(L"explorer32.exe") != std::wstring::npos || image_path.find(L"explorer64.exe") !=
					std::wstring::npos)
				{
					const std::wstring explorer_path = L"C:\\Windows\\Explorer.EXE";
					memset(ptr_unicode->Buffer, 0, ptr_unicode->Length);
					memcpy_s(ptr_unicode->Buffer, ptr_unicode->MaximumLength, explorer_path.c_str(),
					         explorer_path.length() * sizeof(TCHAR));
				}
			}
		}

		if (process_info_class == ProcessBasicInformation)
		{
			information_class_trace = "ProcessBasicInformation";

			if (is_success)
			{
				auto ptr_basic_information = static_cast<PPROCESS_BASIC_INFORMATION>(ptr_out_process_information);
				if (process_info_length == sizeof(PROCESS_EXTENDED_BASIC_INFORMATION))
				{
					ptr_basic_information = &static_cast<PPROCESS_EXTENDED_BASIC_INFORMATION>(
						ptr_out_process_information)->BasicInfo;
				}

				// TODO(GREEN_MACHINE): change PPID (Parent Process ID)
				// Parent PID: InheritedFromUniqueProcessId
				// if target process is fake Explorer change PPID to something (pids are divisible on 4)
				// https://blogs.technet.microsoft.com/markrussinovich/2009/07/05/pushing-the-limits-of-windows-processes-and-threads/
				if (process_name == L"explorer32.exe" || process_name == L"explorer64.exe")
				{
					//dr_printf("PPID: %d\n", ptr_basic_information->InheritedFromUniqueProcessId);
					ptr_basic_information->InheritedFromUniqueProcessId = reinterpret_cast<HANDLE>(0xdeadbeef);
				}
			}
		}

		/// trace call
		json query_info_process;
		query_info_process["NtQueryInformationProcess"]["before"] = {
			{"process_handle", reinterpret_cast<DWORD>(process_handle)},
			{"process_name", process_name_ascii.empty() ? "UNKNOWN" : process_name_ascii.c_str()},
			{"information_class", information_class_trace.c_str()},
		};

		if (process_info_class == ProcessDebugPort)
		{
			query_info_process["NtQueryInformationProcess"]["success"] = is_success;
			dr_printf("[NtQueryInformationProcess] (TID: %d): %s\n", tid, information_class_trace.c_str());
			dr_messagebox("ProcessDebugPort");
		}

		//if (information_class_trace == "UNKNOWN")
		//{
		//	dr_printf("!!!!! %d\n", process_info_class);
		//}

		shared_variables::json_concurrent_vector.push_back(query_info_process);
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtWriteVirtualMemory_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtWriteVirtualMemory(
		//		_In_ HANDLE ProcessHandle,
		//		_In_opt_ PVOID BaseAddress,
		//		_In_reads_bytes_(BufferSize) PVOID Buffer,
		//		_In_ SIZE_T BufferSize,
		//		_Out_opt_ PSIZE_T NumberOfBytesWritten
		//	);

		const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 0));
		const auto ptr_opt_base_address = PVOID(dr_syscall_get_param(drcontext, 1));
		const auto buffer = PVOID(dr_syscall_get_param(drcontext, 2));
		const auto buffer_size = SIZE_T(dr_syscall_get_param(drcontext, 3));
		const auto ptr_out_opt_number_of_bytes_written = PSIZE_T(dr_syscall_get_param(drcontext, 4));

		if (process_handle != nullptr && process_handle != INVALID_HANDLE_VALUE)
		{
			const auto target_process_id = helpers::get_process_id(process_handle);
			const auto target_image_path = helpers::get_process_image_path(process_handle);
			const std::string target_image_path_ascii(target_image_path.begin(), target_image_path.end());

			if (target_process_id != 0U)
			{
				/// trace syscall
				json write_virtual_memory;
				write_virtual_memory["NtWriteVirtualMemory"]["before"] = {
					{"proccess_id", target_process_id},
					{"image_path", target_image_path_ascii.c_str()},
				};
				write_virtual_memory["NtWriteVirtualMemory"]["success"] = false;

				auto target_process_handle = process_handle;
				if (helpers::is_explorer(target_process_id))
				{
					target_process_handle = OpenProcess(GENERIC_ALL, FALSE, shared_variables::dumb_explorer_pid);
				}
				else if (shared_variables::allowed_target_processes.find(target_process_id) == shared_variables::
					allowed_target_processes.end())
				{
					dr_printf("[Access Forbidden] current_pid: %d target_process_id: %d\n", dr_get_process_id(),
					          target_process_id);
					shared_variables::json_concurrent_vector.push_back(write_virtual_memory);
					dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
					return SYSCALL_SKIP;
				}

				const auto return_status = NtWriteVirtualMemory(target_process_handle, ptr_opt_base_address, buffer,
				                                                buffer_size, ptr_out_opt_number_of_bytes_written);

				write_virtual_memory["NtWriteVirtualMemory"]["success"] = NT_SUCCESS(return_status);
				shared_variables::json_concurrent_vector.push_back(write_virtual_memory);

				dr_syscall_set_result(drcontext, return_status);
				return SYSCALL_SKIP;
			}
		}

		//dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
		//return SYSCALL_SKIP;
		return SYSCALL_CONTINUE;
	}

	inline bool NtSuspendProcess_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtSuspendProcess(
		//		_In_ HANDLE ProcessHandle
		//	);

		const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // ProcessHandle
		// we have a process handle, which means it's whitelisted one (NtOpenProcess filters)

		/// trace - before
		const auto process_image_path = helpers::get_process_image_path(process_handle);
		const std::string process_image_path_ascii(process_image_path.begin(), process_image_path.end());
		json suspend_process;
		suspend_process["NtSuspendProcess"]["before"] = {
			{"process_handle", (DWORD)process_handle},
			{"path", process_image_path_ascii.c_str()},
		};

		const auto return_status = NtSuspendProcess(process_handle);

		/// trace - after
		suspend_process["NtSuspendProcess"]["success"] = NT_SUCCESS(return_status) ? true : false;

		shared_variables::json_concurrent_vector.push_back(suspend_process);
		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateProcessEx_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateProcessEx(
		//		_Out_ PHANDLE ProcessHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ HANDLE ParentProcess,
		//		_In_ ULONG Flags,
		//		_In_opt_ HANDLE SectionHandle,
		//		_In_opt_ HANDLE DebugPort,
		//		_In_opt_ HANDLE ExceptionPort,
		//		_In_ ULONG JobMemberLevel
		//	);

		dr_messagebox("[NtCreateProcessEx] implement it!\n");

		dr_syscall_set_result(drcontext, STATUS_NOT_IMPLEMENTED);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateProcess_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateProcess(
		//		_Out_ PHANDLE ProcessHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_ HANDLE ParentProcess,
		//		_In_ BOOLEAN InheritObjectTable,
		//		_In_opt_ HANDLE SectionHandle,
		//		_In_opt_ HANDLE DebugPort,
		//		_In_opt_ HANDLE ExceptionPort
		//	);

		dr_messagebox("[NtCreateProcess] implement it!\n");

		dr_syscall_set_result(drcontext, STATUS_NOT_IMPLEMENTED);
		return SYSCALL_SKIP;
	}

	inline bool NtDelayExecution_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtDelayExecution(
		//		_In_ BOOLEAN Alertable,
		//		_In_opt_ PLARGE_INTEGER DelayInterval
		//	);

		//const auto alertable = BOOLEAN(dr_syscall_get_param(drcontext, 0)); // Alertable
		const auto ptr_opt_delay_interval = PLARGE_INTEGER(dr_syscall_get_param(drcontext, 1)); // DelayInterval

		/// trace syscall
		json delay_execution;

		if (ptr_opt_delay_interval != nullptr)
		{
			delay_execution["NtDelayExecution"]["before"] = {
				{"delay_interval", ptr_opt_delay_interval->QuadPart},
			};
			shared_variables::json_concurrent_vector.push_back(delay_execution);

			//dr_printf("f: 0x%lx\n", ptr_opt_delay_interval->QuadPart);
		}

		//dr_syscall_set_result(drcontext, STATUS_SUCCESS);
		return SYSCALL_CONTINUE;
	}

	inline bool NtOpenThread_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenThread(
		//		_Out_ PHANDLE ThreadHandle,
		//		_In_ ACCESS_MASK DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_opt_ PCLIENT_ID ClientId
		//	);

		const auto ptr_out_thread_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // ThreadHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		// A pointer to a CLIENT_ID structure that identifies the thread whose thread is to be opened.
		const auto ptr_opt_client_id = PCLIENT_ID(dr_syscall_get_param(drcontext, 3)); // ClientId

		// The ObjectName member of this structure must be NULL.
		if ((ptr_object_attributes != nullptr) && (ptr_object_attributes->ObjectName != nullptr))
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		if (ptr_object_attributes == nullptr)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		/// trace syscall
		json nt_open_thread;

		if (ptr_object_attributes->RootDirectory != nullptr)
		{
			dr_printf("[NtOpenThread] RootDirectory != nullptr: 0x%x\n", ptr_object_attributes->RootDirectory);
			dr_messagebox("[NtOpenThread] RootDirectory");
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		if (ptr_opt_client_id != nullptr)
		{
			const auto proc_id = reinterpret_cast<DWORD>(ptr_opt_client_id->UniqueProcess);
			const auto thread_id = reinterpret_cast<DWORD>(ptr_opt_client_id->UniqueThread);

			nt_open_thread["NtOpenThread"]["before"] = {
				{"pid", proc_id},
				{"tid", thread_id},
			};

			if (proc_id != 0U)
			{
				if (helpers::is_explorer(proc_id))
				{
					ptr_opt_client_id->UniqueProcess = reinterpret_cast<HANDLE>(shared_variables::dumb_explorer_pid);
				}
				else if (shared_variables::allowed_target_processes.find(proc_id) == shared_variables::
					allowed_target_processes.end())
				{
					dr_printf("[NtOpenThread] Accessing forbidden process_id: %d\n", proc_id);
					shared_variables::json_concurrent_vector.push_back(nt_open_thread);
					dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
					return SYSCALL_SKIP;
				}
			}
		}

		const auto return_status = NtOpenThread(ptr_out_thread_handle, desired_access, ptr_object_attributes,
		                                        ptr_opt_client_id);

		if (return_status == STATUS_SUCCESS)
		{
			nt_open_thread["NtOpenThread"]["after"] = {
				{"thread_handle", reinterpret_cast<DWORD>(*ptr_out_thread_handle)},
			};
		}
		shared_variables::json_concurrent_vector.push_back(nt_open_thread);

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtCreateUserProcess_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtCreateUserProcess(
		//		_Out_ PHANDLE ProcessHandle,
		//		_Out_ PHANDLE ThreadHandle,
		//		_In_ ACCESS_MASK ProcessDesiredAccess,
		//		_In_ ACCESS_MASK ThreadDesiredAccess,
		//		_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
		//		_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
		//		_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
		//		_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
		//		_In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
		//		_Inout_ PPS_CREATE_INFO CreateInfo,
		//		_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
		//	);

		const auto ptr_out_proc_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // ProcessHandle
		const auto ptr_out_thread_handle = PHANDLE(dr_syscall_get_param(drcontext, 1)); // ThreadHandle
		const auto proc_desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 2));
		const auto thread_desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 3));
		const auto opt_proc_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 4));
		const auto opt_thread_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 5));
		const auto process_flags = ULONG(dr_syscall_get_param(drcontext, 6)); // PROCESS_CREATE_FLAGS_
		const auto thread_flags = ULONG(dr_syscall_get_param(drcontext, 7)); // PROCESS_CREATE_FLAGS_
		const auto ptr_opt_process_parameters = PRTL_USER_PROCESS_PARAMETERS(dr_syscall_get_param(drcontext, 8));
		const auto ptr_create_info = PPS_CREATE_INFO(dr_syscall_get_param(drcontext, 9));
		const auto ptr_opt_attribute_list = PPS_ATTRIBUTE_LIST(dr_syscall_get_param(drcontext, 10));

		if ((opt_proc_object_attributes != nullptr && ((opt_proc_object_attributes->RootDirectory != nullptr) ||
				(opt_proc_object_attributes->ObjectName != nullptr)))
			|| (opt_thread_object_attributes != nullptr && ((opt_thread_object_attributes->RootDirectory != nullptr) ||
				(opt_thread_object_attributes->ObjectName != nullptr))))
		{
			dr_printf("[NtCreateUserProcess] object_attributes. check!\n");
			dr_messagebox("NtCreateUserProcess");
		}

		std::wstring image_path{};
		std::wstring command_line{};
		std::wstring relocated_image_path{};

		if (ptr_opt_process_parameters != nullptr)
		{
			if (ptr_opt_process_parameters->ImagePathName.Buffer != nullptr)
			{
				utils::unicode_string_to_wstring(&ptr_opt_process_parameters->ImagePathName, image_path);

				if (!filesystem::helpers::relocate_path_virtual_fs(image_path, relocated_image_path))
				{
					dr_printf("Failed tp convert a path to virtual one\npath: %ls\n", image_path.c_str());
					dr_syscall_set_result(drcontext, STATUS_OBJECT_NAME_NOT_FOUND);
					return SYSCALL_SKIP;
				}

				if (!relocated_image_path.empty())
				{
					// yeah I know, we leak here (prev. unicode_string buffer ptr)
					RtlCreateUnicodeString(&ptr_opt_process_parameters->ImagePathName, relocated_image_path.data());
				}
			}
			if (ptr_opt_process_parameters->CommandLine.Buffer != nullptr)
			{
				utils::unicode_string_to_wstring(&ptr_opt_process_parameters->CommandLine, command_line);
				const auto image_location = utils::find_case_insensitive(command_line, image_path);
				if (image_location != std::wstring::npos)
				{
					command_line.replace(image_location, image_path.length(), relocated_image_path);
				}
				if (!command_line.empty())
				{
					// yeah I know, we leak here (prev. unicode_string buffer ptr)
					RtlCreateUnicodeString(&ptr_opt_process_parameters->CommandLine, command_line.data());
				}
			}
		}

		if (!fs::exists(relocated_image_path))
		{
			dr_printf("[NtCreateUserProcess] Failed to locate a file: %ls\n", relocated_image_path.c_str());
		}

		/// trace syscall
		const std::string image_path_ascii(image_path.begin(), image_path.end());
		const std::string relocated_path_ascii(relocated_image_path.begin(), relocated_image_path.end());
		const std::string command_line_ascii(command_line.begin(), command_line.end());

		auto target_app_arch = arch::x86_32;
		static_info::get_static_info_and_arch(relocated_path_ascii, target_app_arch);
		const auto is_target_x86 = target_app_arch == arch::x86_32;

		// we need to save "pre call" information and use/save them in "post call" callback
		helpers::create_process_pre_info pre_info{};
		pre_info.image_path_ascii = image_path_ascii;
		pre_info.command_line_ascii = command_line_ascii;
		pre_info.is_x86 = is_target_x86;
		pre_info.is_suspended = thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

		pre_info.ptr_proc_handle = ptr_out_proc_handle;
		pre_info.ptr_thread_handle = ptr_out_thread_handle;

		const auto current_tid = dr_get_thread_id(drcontext);
		if (helpers::pre_create_process_tid.contains(current_tid))
		{
			dr_printf(
				"[NtCreateUserProcess] another syscall from thread %d without returning from the previous one\n",
				current_tid);
			dr_messagebox("NtCreateUserProcess");
		}

		if (target_app_arch != shared_variables::current_app_arch)
		{
			json create_user_process;
			create_user_process["NtCreateUserProcess"]["before"] = {
				{"image_path", pre_info.image_path_ascii.c_str()},
				{"command_line", pre_info.command_line_ascii.c_str()},
				{"is_x86", pre_info.is_x86},
				{"is_suspended", pre_info.is_suspended},
			};
			create_user_process["NtCreateUserProcess"]["success"] = false;
			shared_variables::json_concurrent_vector.push_back(create_user_process);

			dr_printf(
				"[NtCreateUserProcess] Cross-platform arch execution is not currently supported!\nPath: %s\n",
				image_path_ascii.c_str());
			dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
			return SYSCALL_SKIP;
		}

		helpers::pre_create_process_tid[current_tid] = pre_info;

		//dr_printf("[NtCreateUserProcess] {%s} path: %s\nrelocated: %ls\ncmd: %ls\n", is_target_x86 ? "x86" : "x64",
		//          image_path_ascii.c_str(), ptr_opt_process_parameters->ImagePathName.Buffer, ptr_opt_process_parameters->CommandLine.Buffer);

		shared_variables::are_children = true;
		// SYSCALL_CONTINUE => inject child process

		return SYSCALL_CONTINUE;
	}

	inline void NtCreateUserProcess_post_handler(void* drcontext)
	{
		const NTSTATUS return_value = dr_syscall_get_result(drcontext);
		const auto current_tid = dr_get_thread_id(drcontext);

		if (!helpers::pre_create_process_tid.contains(current_tid))
		{
			dr_printf("[NtCreateUserProcess_Post] No thread ID: %d, in pre call container\n", current_tid);
			dr_messagebox("NtCreateUserProcess_Post");
			return;
		}
		const auto pre_info = helpers::pre_create_process_tid[current_tid];
		helpers::pre_create_process_tid.erase(current_tid);

		json create_user_process;
		create_user_process["NtCreateUserProcess"]["before"] = {
			{"image_path", pre_info.image_path_ascii.c_str()},
			{"command_line", pre_info.command_line_ascii.c_str()},
			{"is_x86", pre_info.is_x86},
			{"is_suspended", pre_info.is_suspended},
		};

		if (!NT_SUCCESS(return_value))
		{
			if (return_value == STATUS_OBJECT_NAME_NOT_FOUND)
			{
				dr_printf("[Dr.Semu:NtCreateProcess:Post] OBJECT_NAME_NOT_FOUND: %s\n",
				          pre_info.image_path_ascii.c_str());
			}
			else
			{
				dr_printf("[CreateUserProcess] Error: 0x%lx\n", return_value);
			}
			create_user_process["NtCreateUserProcess"]["success"] = false;
			shared_variables::json_concurrent_vector.push_back(create_user_process);
		}
		else
		{
			const auto proc_id = GetProcessId(*pre_info.ptr_proc_handle);
			const auto thread_id = GetThreadId(*pre_info.ptr_thread_handle);

			// whitelist a child process
			shared_variables::allowed_target_processes.insert(proc_id);

			create_user_process["NtCreateUserProcess"]["after"]["proc_id"] = proc_id;
			create_user_process["NtCreateUserProcess"]["after"]["thread_id"] = thread_id;

			create_user_process["NtCreateUserProcess"]["success"] = true;
			shared_variables::json_concurrent_vector.push_back(create_user_process);
		}
	}

	inline bool NtOpenProcess_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtOpenProcess(
		//		_Out_ PHANDLE ProcessHandle,
		//		_In_ desired_access DesiredAccess,
		//		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		//		_In_opt_ PCLIENT_ID ClientId
		//	);

		const auto ptr_out_handle = PHANDLE(dr_syscall_get_param(drcontext, 0)); // ProcessHandle
		const auto desired_access = ACCESS_MASK(dr_syscall_get_param(drcontext, 1)); // DesiredAccess
		const auto ptr_object_attributes = POBJECT_ATTRIBUTES(dr_syscall_get_param(drcontext, 2)); // ObjectAttributes
		auto ptr_opt_client_id = PCLIENT_ID(dr_syscall_get_param(drcontext, 3)); // ClientId

		if (ptr_object_attributes == nullptr)
		{
			dr_syscall_set_result(drcontext, STATUS_INVALID_PARAMETER);
			return SYSCALL_SKIP;
		}

		if (ptr_object_attributes->RootDirectory != nullptr || ptr_object_attributes->ObjectName != nullptr)
		{
			dr_printf("[NtOpenProcess] rootDir: 0x%x\n", ptr_object_attributes->RootDirectory);
			if (ptr_object_attributes->ObjectName != nullptr)
			{
				dr_printf("Object_Name: %ls\n", ptr_object_attributes->ObjectName->Buffer);
			}
			dr_messagebox("[NtOpenProcess] interesting case");
		}

		/// trace syscall
		json nt_open_process;
		nt_open_process["NtOpenProcess"]["before"] = {
			{"desired_access", desired_access},
			{"pid", ptr_opt_client_id != nullptr ? reinterpret_cast<DWORD>(ptr_opt_client_id->UniqueProcess) : 0},
			{"tid", ptr_opt_client_id != nullptr ? reinterpret_cast<DWORD>(ptr_opt_client_id->UniqueThread) : 0},
		};
		nt_open_process["NtOpenProcess"]["success"] = false;

		if (ptr_opt_client_id != nullptr)
		{
			const auto access_process_id = reinterpret_cast<DWORD>(ptr_opt_client_id->UniqueProcess);
			if (access_process_id != 0U)
			{
				if (helpers::is_explorer(access_process_id))
				{
					ptr_opt_client_id->UniqueProcess = HANDLE(shared_variables::dumb_explorer_pid);
				}
				else if (shared_variables::allowed_target_processes.find(access_process_id) == shared_variables::
					allowed_target_processes.end())
				{
					//dr_printf("Accessing forbidden process_id: %d\n", access_process_id);
					shared_variables::json_concurrent_vector.push_back(nt_open_process);
					dr_syscall_set_result(drcontext, STATUS_ACCESS_DENIED);
					return SYSCALL_SKIP;
				}
			}
		}

		const auto return_status = NtOpenProcess(ptr_out_handle, desired_access, ptr_object_attributes,
		                                         ptr_opt_client_id);
		const auto is_success = NT_SUCCESS(return_status);

		nt_open_process["NtOpenProcess"]["success"] = is_success;
		if (is_success)
		{
			nt_open_process["NtOpenProcess"]["after"] = {
				{"process_handle", reinterpret_cast<DWORD>(*ptr_out_handle)},
			};
		}
		//shared_variables::json_concurrent_vector.push_back(nt_open_process);

		dr_syscall_set_result(drcontext, return_status);
		return SYSCALL_SKIP;
	}

	inline bool NtQueryVirtualMemory_handler(void* drcontext)
	{
		//NTSYSCALLAPI
		//	NTSTATUS
		//	NTAPI
		//	NtQueryVirtualMemory(
		//		_In_ HANDLE ProcessHandle,
		//		_In_opt_ PVOID BaseAddress,
		//		_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
		//		_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
		//		_In_ SIZE_T MemoryInformationLength,
		//		_Out_opt_ PSIZE_T ReturnLength
		//	);


		//const auto process_handle = HANDLE(dr_syscall_get_param(drcontext, 0)); // ProcessHandle

		// nothing to hide, maybe some loggings
		return SYSCALL_CONTINUE;
	}
} // namespace dr_semu::process::handlers
