#include "includes.h"

#include "filesystem_handlers.hpp"
#include "registry_handlers.hpp"
#include "process_handlers.hpp"
#include "system_handlers.hpp"
#include "COM_handlers.hpp"
#include "networking_handlers.hpp"
#include "object_handlers.hpp"

#include "droption.h"
#include "drwrap.h"
#include "drx.h"

#include <chrono>

#define WINDOWS

static void
event_exit();

void add_current_process();
void remove_current_process();

static bool
event_filter_syscall(void* drcontext, int sysnum);
static bool
event_pre_syscall(void* drcontext, int sysnum);
static void
event_post_syscall(void* drcontext, int sysnum);

static void module_load_event(void* drcontext, const module_data_t* mod, bool Loaded);

void sleep_and_die(void* limit)
{
	const auto time_limit = reinterpret_cast<DWORD>(limit);
	dr_sleep(time_limit SECONDS);
	
	dr_exit_process(0);
}

inline std::wstring get_virtual_root_device_form()
{
	TCHAR device_name[MAX_PATH]{};
	if (dr_semu::shared_variables::virtual_filesystem_path.empty())
	{
		dr_printf("v_fs_location variable is empty\n");
		return {};
	}
	const std::wstring virtual_drive_name(dr_semu::shared_variables::virtual_filesystem_path, 0, 2);
	// C:\dir2\dir2 => C:
	QueryDosDevice(virtual_drive_name.c_str(), device_name, MAX_PATH);

	const std::wstring device_path(device_name, wcslen(device_name));

	return device_path + std::wstring{dr_semu::shared_variables::virtual_filesystem_path, 2};
}

inline std::vector<std::wstring> get_drive_strings();


enum
{
	NUDGE_TERMINATE_PROCESS = 1,
};

static client_id_t client_id;

static void
nudge_event(void* drcontext, const uint64 argument)
{
	const auto nudge_arg = static_cast<int>(argument);
	const auto exit_arg = static_cast<int>(argument >> 32);
	if (nudge_arg == NUDGE_TERMINATE_PROCESS)
	{
		static int nudge_term_count;
		/* handle multiple from both NtTerminateProcess and NtTerminateJobObject */
		const uint count = dr_atomic_add32_return_sum(&nudge_term_count, 1);
		if (count == 1)
		{
			dr_exit_process(exit_arg);
		}
	}
}

static bool
soft_kill_event(process_id_t pid, int exit_code)
{
	const auto result = dr_nudge_client_ex(pid, client_id,
	                                       NUDGE_TERMINATE_PROCESS | static_cast<uint64>(exit_code) << 32,
	                                       0);
	// if false, a target is not under DR
	return result == DR_SUCCESS;
}

static DWORD get_parent_id()
{
	ULONG return_length{};
	PROCESS_BASIC_INFORMATION process_basic_information{};
	const auto return_status = NtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessBasicInformation,
		&process_basic_information,
		sizeof(PROCESS_BASIC_INFORMATION),
		&return_length);
	if (!NT_SUCCESS(return_status))
	{
		return -1;
	}
	return reinterpret_cast<DWORD>(process_basic_information.InheritedFromUniqueProcessId);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char* argv[])
{
	dr_set_client_name("Dr.Semu",
	                   "https://github.com/secrary/DrSemu");

	drmgr_init();
	drwrap_init();
	drx_init();

	client_id = id;

	if (dr_is_notify_on())
	{
		dr_enable_console_printing();
	}

	dr_register_nudge_event(nudge_event, client_id);
	drx_register_soft_kills(soft_kill_event);

	/// https://dynamorio.org/docs/page_droption.html
	droption_t<unsigned int> vm_index_option(DROPTION_SCOPE_CLIENT, "vm", 0, "vm index", "VM index number");
	droption_t<unsigned int> dumb_pid_option(DROPTION_SCOPE_CLIENT, "pid", 0, "dumb explorer pid",
	                                         "dumb explorer pid [LONG DESC]");
	droption_t<std::string> binaries_dir_option(DROPTION_SCOPE_CLIENT, "bin", "", "bin_dir",
	                                            "location of binaries");
	droption_t<std::string> temp_directory(DROPTION_SCOPE_CLIENT, "dir", "", "VM location",
	                                       "VM directory for current instance");
	droption_t<std::string> report_name_option(DROPTION_SCOPE_CLIENT, "report", "", "report name",
	                                           "report directory name");
	droption_t<std::string> main_mailslot_name_option(DROPTION_SCOPE_CLIENT, "main_slot", "", "main mailslot",
	                                                  "main mailslot name");
	droption_t<unsigned int> time_limit_option(DROPTION_SCOPE_CLIENT, "limit", 0, "limit",
	                                        "target application will die after _TIME_LIMIT_");

	dr_semu::networking::config::disable_internet = false;

	std::string parse_err;
	int last_index{};
	if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_index))
	{
		dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
		dr_messagebox("argument parsing error");
		dr_abort();
	}

	auto is_explorer = false;
	dr_semu::shared_variables::dumb_explorer_pid = dumb_pid_option.get_value();
	if (dr_semu::shared_variables::dumb_explorer_pid == 0)
	{
		is_explorer = true;
		dr_semu::shared_variables::dumb_explorer_pid = dr_get_process_id();
	}
	const auto mailslot_name_string = main_mailslot_name_option.get_value();
	dr_semu::shared_variables::main_launcher_slot_name = std::wstring(mailslot_name_string.begin(),
	                                                                  mailslot_name_string.end());
	const auto binary_directory_string = binaries_dir_option.get_value();
	dr_semu::shared_variables::binary_directory = std::wstring(binary_directory_string.begin(),
	                                                           binary_directory_string.end());
	const auto report_directory_name_string = report_name_option.get_value();
	dr_semu::shared_variables::report_directory_name = std::wstring(report_directory_name_string.begin(),
	                                                                report_directory_name_string.end());
	const auto time_limit = time_limit_option.get_value();
	
	//dr_printf("Explorer ID: %d\nmain: %ls\nbin_dir: %ls\nreport: %ls\n",
	//          dr_semu::shared_variables::dumb_explorer_pid,
	//          dr_semu::shared_variables::main_launcher_slot_name.c_str(),
	//          dr_semu::shared_variables::binary_directory.c_str(),
	//          dr_semu::shared_variables::report_directory_name.c_str());

	if (dr_semu::shared_variables::dumb_explorer_pid == 0 ||
		dr_semu::shared_variables::main_launcher_slot_name.empty() ||
		dr_semu::shared_variables::binary_directory.empty() ||
		dr_semu::shared_variables::report_directory_name.empty()
	)
	{
		dr_printf("[Dr.Semu] Invalid parameters\n");
		dr_messagebox("[Dr.Semu] invalid arguments");
		dr_abort();
	}

	add_current_process();

	const auto temp_dir_ascii = temp_directory.get_value();
	if (temp_dir_ascii.empty())
	{
		dr_printf("Failed to get temp directory\n");
		dr_abort();
	}
	std::wstring temp_dir(temp_dir_ascii.begin(), temp_dir_ascii.end());

	const auto vm_index = vm_index_option.get_value();
	dr_semu::shared_variables::current_vm_name = L"dr_semu_" + std::to_wstring(vm_index);
	dr_semu::shared_variables::virtual_filesystem_path = fs::path{
		temp_dir + dr_semu::shared_variables::current_vm_name
	};
	dr_semu::shared_variables::v_fs_device_form = get_virtual_root_device_form();

	/// static_info
	auto target_module = dr_get_main_module();
	std::string application_full_path{};
	if (target_module == nullptr)
	{
		dr_printf("[Dr.Semu] Failed to get a target module\n");
	}
	else
	{
		application_full_path = target_module->full_path;
		dr_printf("[Dr.Semu] File path: %s\n", application_full_path.c_str());
		dr_free_module_data(target_module);
	}

	if (time_limit != 0)
	{
		// set timer
		dr_create_client_thread(sleep_and_die, reinterpret_cast<PVOID>(time_limit));
	}

	// Assume that a host OS is 64-bit
	dr_semu::shared_variables::current_app_arch = dr_is_wow64() ? dr_semu::arch::x86_32 : dr_semu::arch::x86_64;

	if (!application_full_path.empty())
	{
		if (!is_explorer)
		{
			if (!dr_semu::static_info::get_static_info_and_arch(application_full_path,
			                                                    dr_semu::shared_variables::current_app_arch))
			{
				dr_printf("[Dr.Semu] failed to get a static information\npath: %s\n",
				          application_full_path.c_str());
				dr_messagebox("failed: static info");
				dr_abort();
			}
		}
		// static information from a fake Explorer is not interesting...
	}

	if (!dr_semu_init())
	{
		dr_printf("Failed to get syscall numbers\n");
		dr_messagebox("Failed to get syscall numbers");
		return;
	}

	const auto current_proc_id = dr_get_process_id();
	dr_semu::shared_variables::allowed_target_processes.insert(current_proc_id);
	const auto parent_proc_id = get_parent_id();
	dr_semu::shared_variables::allowed_target_processes.insert(parent_proc_id);

	dr_register_filter_syscall_event(event_filter_syscall);
	drmgr_register_pre_syscall_event(event_pre_syscall);
	drmgr_register_post_syscall_event(event_post_syscall);
	drmgr_register_module_load_event(module_load_event);

	dr_register_exit_event(event_exit);

	// add Dr.Semu related processes
	dr_semu::shared_variables::semu_process_names.insert(L"drrun.exe");
	dr_semu::shared_variables::semu_process_names.insert(L"explorer32.exe");
	dr_semu::shared_variables::semu_process_names.insert(L"explorer64.exe");

	if (is_explorer)
	{
		dr_semu::utils::hide_fake_explorer();
	}

	dr_semu::shared_variables::initial_time = std::chrono::high_resolution_clock::now();
	
	//dr_printf("dr_main_end\n");
}

inline std::vector<std::wstring> get_drive_strings()
{
	// [GetLogicalDriveStrings] The return value is the length, in characters, of the strings copied to the buffer, not including the terminating null character
	const auto size = GetLogicalDriveStrings(0, nullptr);
	const std::shared_ptr<TCHAR> disk_drives{new TCHAR[size + 1]{}};
	GetLogicalDriveStrings(size, disk_drives.get());

	std::vector<std::wstring> drives_vector{};
	auto drive_ptr = disk_drives.get();
	while (*drive_ptr != 0U)
	{
		const auto current_string_size = wcslen(drive_ptr);
		const std::wstring current_drive{drive_ptr, current_string_size};
		drives_vector.emplace_back(current_drive);
		drive_ptr += (current_string_size + 1);
	}

	return drives_vector;
}

void add_current_process()
{
	if (dr_semu::shared_variables::main_launcher_slot_name.empty())
	{
		dr_printf("A launcher slot name is empty\n");
		return;
	}
	const dr_semu::shared::slot main_launcher_slot(dr_semu::shared_variables::main_launcher_slot_name, false);
	if (!main_launcher_slot.is_valid())
	{
		DR_ASSERT(FALSE && "failed to connect mailslot [main_launcher_slot]");
	}
	const auto add_command{std::wstring{L"add"} + L" " + std::to_wstring(dr_get_process_id())};
	const auto result = main_launcher_slot.write_slot(add_command);
	if (!result)
	{
		dr_messagebox("[add_current_process] failed.");
		dr_abort();
	}
}

void remove_current_process()
{
	const dr_semu::shared::slot main_launcher_slot(dr_semu::shared_variables::main_launcher_slot_name, false);
	if (!main_launcher_slot.is_valid())
	{
		DR_ASSERT(FALSE && "failed to connect mailslot [main_launcher_slot]");
	}
	const auto add_command{std::wstring{L"remove"} + L" " + std::to_wstring(dr_get_process_id())};
	const auto result = main_launcher_slot.write_slot(add_command);
	if (!result)
	{
		dr_messagebox("[remove_current_process] failed.");
		dr_abort();
	}
}

static void
event_exit()
{
	const auto end_time = std::chrono::high_resolution_clock::now();
	const auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - dr_semu::shared_variables::initial_time).count();

	dr_printf("[event_exit] PID: %d\tDuration: %d seconds\n", dr_get_process_id(), duration);

	
	drmgr_unregister_module_load_event(module_load_event);
	if (!drmgr_unregister_pre_syscall_event(event_pre_syscall) || !drmgr_unregister_post_syscall_event(
		event_post_syscall))
	{
		dr_printf("Failed to unregister [PRE_SYSCALL/POST_SYSCALL]");
	}
	drx_exit();
	drwrap_exit();
	drmgr_exit();


	const auto current_proc_id = dr_get_process_id();
	const auto current_proc_id_string = std::to_string(current_proc_id);

	dr_printf("\n --- EOF PID: %d --- \n", current_proc_id);

	json json_dynamic;
	if (!dr_semu::shared_variables::json_concurrent_vector.empty())
	{
		json_dynamic = dr_semu::shared_variables::json_concurrent_vector;
	}
	else
	{
		json_dynamic["empty"] = 1;
	}
	// json_reports/name_pid.json
	const auto report_directory_wide = dr_semu::shared_variables::binary_directory + dr_semu::shared_variables::
		report_directory_name;
	const std::string report_directory(report_directory_wide.begin(), report_directory_wide.end());
	if (!dr_directory_exists(report_directory.c_str()))
	{
		dr_create_dir(report_directory.c_str());
	}
	const std::string application_name = dr_get_application_name();
	const auto out_json_file = dr_open_file(
		(report_directory + "\\" + current_proc_id_string + ".json").c_str(),
		DR_FILE_WRITE_OVERWRITE);
	const auto json_str = json_dynamic.dump();
	dr_write_file(out_json_file, json_str.data(), json_str.length());
	dr_close_file(out_json_file);

	const auto msg_string = std::string{"END! PROC: "} + dr_get_application_name() + " PID: " + std::to_string(
		dr_get_process_id());
	dr_messagebox(msg_string.c_str());

	/*
	ISSUE: if a parent process calls remove_current_process before a child process(es) finish dr_client_main execution
	and call add_current_process
	SOLUTION: sleep 5 secs
	*/
	if (dr_semu::shared_variables::are_children)
	{
		dr_sleep(5 SECONDS);
	}

	/// end_command to a launcher
	remove_current_process();
}


static bool
event_filter_syscall(void* drcontext, int sysnum)
{
	return dr_semu::syscall::syscall_numbers.find(sysnum) != dr_semu::syscall::syscall_numbers.end();
}

static bool
event_pre_syscall(void* drcontext, int sysnum)
{
	// handle syscalls
	if (dr_semu::syscall::syscall_numbers.find(sysnum) != dr_semu::syscall::syscall_numbers.end())
	{
		const auto syscall_name = dr_semu::syscall::syscall_numbers[sysnum];
		//dr_printf("sys_name [%d]: %s\n", dr_get_thread_id(drcontext), syscall_name.c_str()); 

		//return SYSCALL_CONTINUE;
		if (syscall_name == NTWRITEFILE)
		{
			return dr_semu::filesystem::handlers::NtWriteFile_handler(drcontext);
		}
		if (syscall_name == NTCLOSE)
		{
			return dr_semu::filesystem::handlers::NtClose_handler(drcontext);
		}
		if (syscall_name == NTQUERYVIRTUALMEMORY)
		{
			return dr_semu::process::handlers::NtQueryVirtualMemory_handler(drcontext);
		}
		if (syscall_name == NTQUERYINFORMATIONPROCESS)
		{
			return dr_semu::process::handlers::NtQueryInformationProcess_handler(drcontext);
		}
		if (syscall_name == NTCREATEFILE)
		{
			return dr_semu::filesystem::handlers::NtCreateFile_handler(drcontext);
		}
		if (syscall_name == NTOPENFILE)
		{
			return dr_semu::filesystem::handlers::NtOpenFile_handler(drcontext);
		}
		if (syscall_name == NTCREATESECTION)
		{
			return dr_semu::filesystem::handlers::NtCreateSection_handler(drcontext);
		}
		if (syscall_name == NTMAPVIEWOFSECTION)
		{
			return dr_semu::filesystem::handlers::NtMapViewOfSection_hook(drcontext);
		}
		if (syscall_name == NTQUERYINFORMATIONFILE)
		{
			return dr_semu::filesystem::handlers::NtQueryInformationFile_hook(drcontext);
		}
		if (syscall_name == NTSETINFORMATIONFILE)
		{
			return dr_semu::filesystem::handlers::NtSetInformationFile_hook(drcontext);
		}
		if (syscall_name == NTQUERYATTRIBUTESFILE)
		{
			return dr_semu::filesystem::handlers::NtQueryAttributesFile_hook(drcontext);
		}
		if (syscall_name == NTDELETEFILE)
		{
			return dr_semu::filesystem::handlers::NtDeleteFile_handler(drcontext);
		}
		if (syscall_name == NTCREATEDIRECTORYOBJECT)
		{
			return dr_semu::filesystem::handlers::NtCreateDirectoryObject_hook(drcontext);
		}
		if (syscall_name == NTCREATEPAGINGFILE)
		{
			return dr_semu::filesystem::handlers::NtCreatePagingFile_handler(drcontext);
		}
		if (syscall_name == NTCREATEIOCOMPLETION)
		{
			return dr_semu::filesystem::handlers::NtCreateIoCompletion_handler(drcontext);
		}
		if (syscall_name == NTQUERYFULLATTRIBUTESFILE)
		{
			return dr_semu::filesystem::handlers::NtQueryFullAttributesFile_handler(drcontext);
		}
		if (syscall_name == NTQUERYDIRECTORYFILE)
		{
			return dr_semu::filesystem::handlers::NtQueryDirectoryFile_handler(drcontext);
		}
		if (syscall_name == NTQUERYDIRECTORYFILEEX)
		{
			return dr_semu::filesystem::handlers::NtQueryDirectoryFileEx_handler(drcontext);
		}
		if (syscall_name == NTCREATESYMBOLICLINKOBJECT)
		{
			return dr_semu::filesystem::handlers::NtCreateSymbolicLinkObject_handler(drcontext);
		}
		if (syscall_name == NTFLUSHBUFFERSFILE)
		{
			return dr_semu::filesystem::handlers::NtFlushBuffersFile_handler(drcontext);
		}


		// registry
		if (syscall_name == NTOPENKEY)
		{
			return dr_semu::registry::handlers::NtOpenKey_handler(drcontext);
		}
		if (syscall_name == NTOPENKEYEX)
		{
			return dr_semu::registry::handlers::NtOpenKeyEx_handler(drcontext);
		}
		if (syscall_name == NTCREATEKEY)
		{
			return dr_semu::registry::handlers::NtCreateKey_handler(drcontext);
		}
		if (syscall_name == NTDELETEVALUEKEY)
		{
			return dr_semu::registry::handlers::NtDeleteValueKey_handler(drcontext);
		}
		if (syscall_name == NTDELETEKEY)
		{
			return dr_semu::registry::handlers::NtDeleteKey_handler(drcontext);
		}
		if (syscall_name == NTQUERYVALUEKEY)
		{
			return dr_semu::registry::handlers::NtQueryValueKey_handler(drcontext);
		}
		if (syscall_name == NTQUERYKEY)
		{
			return dr_semu::registry::handlers::NtQueryKey_handler(drcontext);
		}
		if (syscall_name == NTENUMERATEKEY)
		{
			return dr_semu::registry::handlers::NtEnumerateKey_handler(drcontext);
		}
		if (syscall_name == NTENUMERATEVALUEKEY)
		{
			return dr_semu::registry::handlers::NtEnumerateValueKey_handler(drcontext);
		}
		if (syscall_name == NTSETVALUEKEY)
		{
			return dr_semu::registry::handlers::NtSetValueKey_handler(drcontext);
		}
		if (syscall_name == NTNOTIFYCHANGEKEY)
		{
			return dr_semu::registry::handlers::NtNotifyChangeKey_handler(drcontext);
		}
		if (syscall_name == NTNOTIFYCHANGEMULTIPLEKEYS)
		{
			return dr_semu::registry::handlers::NtNotifyChangeMultipleKeys_handler(drcontext);
		}

		if (syscall_name == NTCREATEKEYTRANSACTED)
		{
			return dr_semu::registry::handlers::NtCreateKeyTransacted_handler(drcontext);
		}
		if (syscall_name == NTOPENKEYTRANSACTED)
		{
			return dr_semu::registry::handlers::NtOpenKeyTransacted_handler(drcontext);
		}
		if (syscall_name == NTOPENKEYTRANSACTEDEX)
		{
			return dr_semu::registry::handlers::NtOpenKeyTransactedEx_handler(drcontext);
		}
		if (syscall_name == NTCOMPACTKEYS)
		{
			return dr_semu::registry::handlers::NtCompactKeys_handler(drcontext);
		}
		if (syscall_name == NTCOMPRESSKEY)
		{
			return dr_semu::registry::handlers::NtCompressKey_handler(drcontext);
		}
		if (syscall_name == NTFLUSHKEY)
		{
			return dr_semu::registry::handlers::NtFlushKey_handler(drcontext);
		}
		if (syscall_name == NTFREEZEREGISTRY)
		{
			return dr_semu::registry::handlers::NtFreezeRegistry_handler(drcontext);
		}
		if (syscall_name == NTINITIALIZEREGISTRY)
		{
			return dr_semu::registry::handlers::NtInitializeRegistry_handler(drcontext);
		}
		if (syscall_name == NTLOADKEY)
		{
			return dr_semu::registry::handlers::NtLoadKey_handler(drcontext);
		}
		if (syscall_name == NTSAVEKEY)
		{
			return dr_semu::registry::handlers::NtSaveKey_handler(drcontext);
		}
		if (syscall_name == NTSAVEKEYEX)
		{
			return dr_semu::registry::handlers::NtSaveKeyEx_handler(drcontext);
		}
		if (syscall_name == NTLOADKEY2)
		{
			return dr_semu::registry::handlers::NtLoadKey2_handler(drcontext);
		}
		if (syscall_name == NTLOADKEYEX)
		{
			return dr_semu::registry::handlers::NtLoadKeyEx_handler(drcontext);
		}
		if (syscall_name == NTLOCKREGISTRYKEY)
		{
			return dr_semu::registry::handlers::NtLockRegistryKey_handler(drcontext);
		}
		if (syscall_name == NTQUERYMULTIPLEVALUEKEY)
		{
			return dr_semu::registry::handlers::NtQueryMultipleValueKey_handler(drcontext);
		}
		if (syscall_name == NTQUERYOPENSUBKEYS)
		{
			return dr_semu::registry::handlers::NtQueryOpenSubKeys_handler(drcontext);
		}
		if (syscall_name == NTQUERYOPENSUBKEYSEX)
		{
			return dr_semu::registry::handlers::NtQueryOpenSubKeysEx_handler(drcontext);
		}


		// processes and threads
		if (syscall_name == NTOPENPROCESS)
		{
			return dr_semu::process::handlers::NtOpenProcess_handler(drcontext);
		}
		if (syscall_name == NTCREATEUSERPROCESS)
		{
			return dr_semu::process::handlers::NtCreateUserProcess_handler(drcontext);
		}
		if (syscall_name == NTOPENTHREAD)
		{
			return dr_semu::process::handlers::NtOpenThread_handler(drcontext);
		}
		if (syscall_name == NTDELAYEXECUTION)
		{
			return dr_semu::process::handlers::NtDelayExecution_handler(drcontext);
		}
		if (syscall_name == NTCREATEPROCESS)
		{
			return dr_semu::process::handlers::NtCreateProcess_handler(drcontext);
		}
		if (syscall_name == NTCREATEPROCESSEX)
		{
			return dr_semu::process::handlers::NtCreateProcessEx_handler(drcontext);
		}
		if (syscall_name == NTSUSPENDPROCESS)
		{
			return dr_semu::process::handlers::NtSuspendProcess_handler(drcontext);
		}
		if (syscall_name == ntwritevirtualmemory)
		{
			return dr_semu::process::handlers::NtWriteVirtualMemory_handler(drcontext);
		}
		if (syscall_name == ntsetinformationprocess)
		{
			return dr_semu::process::handlers::NtSetInformationProcess_handler(drcontext);
		}
		if (syscall_name == ntcontinue)
		{
			return dr_semu::process::handlers::NtContinue_handler(drcontext);
		}
		if (syscall_name == ntprotectvirtualmemory)
		{
			return dr_semu::process::handlers::NtProtectVirtualMemory_handler(drcontext);
		}
		if (syscall_name == ntsetcontextthread)
		{
			return dr_semu::process::handlers::NtSetContextThread_handler(drcontext);
		}

		// system related
		if (syscall_name == ntquerysysteminformation)
		{
			return dr_semu::system::handlers::NtQuerySystemInformation_handler(drcontext);
		}
		if (syscall_name == ntloaddriver)
		{
			return dr_semu::system::handlers::NtLoadDriver_handler(drcontext);
		}
		if (syscall_name == ntusersystemparametersinfo)
		{
			return dr_semu::system::handlers::NtUserSystemParametersInfo_handler(drcontext);
		}
		if (syscall_name == ntraiseharderror)
		{
			return dr_semu::system::handlers::NtRaiseHardError_handler(drcontext);
		}

		// objects
		if (syscall_name == ntcreatemutant)
		{
			return dr_semu::objects::handlers::NtCreateMutant_handler(drcontext);
		}
		if (syscall_name == ntopenmutant)
		{
			return dr_semu::objects::handlers::NtOpenMutant_handler(drcontext);
		}
		if (syscall_name == ntcreatemailslotfile)
		{
			return dr_semu::objects::handlers::NtCreateMailslotFile_handler(drcontext);
		}
		if (syscall_name == ntcreatesemaphore)
		{
			return dr_semu::objects::handlers::NtCreateSemaphore_handler(drcontext);
		}
		if (syscall_name == ntopensemaphore)
		{
			return dr_semu::objects::handlers::NtOpenSemaphore_handler(drcontext);
		}
		if (syscall_name == ntcreateevent)
		{
			return dr_semu::objects::handlers::NtCreateEvent_handler(drcontext);
		}
		if (syscall_name == ntopenevent)
		{
			return dr_semu::objects::handlers::NtOpenEvent_handler(drcontext);
		}
		if (syscall_name == ntwaitforsingleobject)
		{
			return dr_semu::objects::handlers::NtWaitForSingleObject_handler(drcontext);
		}
		if (syscall_name == ntqueryobject)
		{
			return dr_semu::objects::handlers::NtQueryObject_handler(drcontext);
		}

		return dr_semu::SYSCALL_CONTINUE;
	}

	return true; /* execute normally */
}

void event_post_syscall(void* drcontext, int sysnum)
{
	if (dr_semu::syscall::syscall_numbers.find(sysnum) != dr_semu::syscall::syscall_numbers.end())
	{
		const auto syscall_name = dr_semu::syscall::syscall_numbers[sysnum];
		// ... post syscall

		if (syscall_name == NTCREATEUSERPROCESS)
		{
			dr_semu::process::handlers::NtCreateUserProcess_post_handler(drcontext);
		}
	}
}

static bool wrap_function(
	const module_handle_t handle, const std::string& function_name,
	void (*pre_func_cb)(void* wrapcxt, OUT void** user_data),
	void (*post_func_cb)(void* wrapcxt, void* user_data)
)
{
	const auto ptr_get_class_object = reinterpret_cast<app_pc>(dr_get_proc_address(handle, function_name.c_str()));
	if (ptr_get_class_object != nullptr)
	{
		return !drwrap_wrap(ptr_get_class_object, pre_func_cb, post_func_cb);
	}
	return false;
}


void module_load_event(void* drcontext, const module_data_t* mod, bool Loaded)
{
	// COM

	// CoCreateInstance and CoCreateInstanceEx 
	wrap_function(mod->handle, "CoCreateInstance", dr_semu::com::handlers::pre_co_create_instance, nullptr);
	wrap_function(mod->handle, "CoCreateInstanceEx", dr_semu::com::handlers::pre_co_create_instance_ex, nullptr);
	// CoGetClassObject
	wrap_function(mod->handle, "CoGetClassObject", dr_semu::com::handlers::pre_get_class_object, nullptr);

	// Networking
	wrap_function(mod->handle, "WSAStartup", dr_semu::networking::handlers::pro_wsa_startup, nullptr);
	wrap_function(mod->handle, "URLDownloadToFileW", dr_semu::networking::handlers::pro_url_download_to_file, nullptr);
	wrap_function(mod->handle, "URLDownloadToCacheFileW", dr_semu::networking::handlers::pro_url_download_to_cache_file,
	              nullptr);
	wrap_function(mod->handle, "gethostbyname", dr_semu::networking::handlers::pro_gethostbyname, nullptr);
	wrap_function(mod->handle, "InternetOpenUrl", dr_semu::networking::handlers::pro_InternetOpenUrl, nullptr);
}
