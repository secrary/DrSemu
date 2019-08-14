#pragma once

//#define disable_all_handlers
#define xxx dr_printf("check! line: %d function: %ls\n", __LINE__, __FUNCTIONW__);

#define PAGE_SIZE 0x1000

//#define NO_TRACE_FILESYSTEM

// filesystem
#define NTWRITEFILE					"NtWriteFile"
#define NTCLOSE						"NtClose"
#define NTCREATEFILE				"NtCreateFile"
#define NTOPENFILE					"NtOpenFile"
#define NTCREATESECTION				"NtCreateSection"
#define	NTMAPVIEWOFSECTION			"NtMapViewOfSection"
#define NTQUERYINFORMATIONFILE		"NtQueryInformationFile"
#define NTSETINFORMATIONFILE		"NtSetInformationFile"
#define NTQUERYATTRIBUTESFILE		"NtQueryAttributesFile"
#define NTDELETEFILE				"NtDeleteFile"
#define NTCREATEDIRECTORYOBJECT		"NtCreateDirectoryObject"
#define NTCREATEPAGINGFILE			"NtCreatePagingFile"
#define NTCREATEIOCOMPLETION		"NtCreateIoCompletion"
#define NTQUERYFULLATTRIBUTESFILE	"NtQueryFullAttributesFile"
#define NTQUERYDIRECTORYFILE		"NtQueryDirectoryFile"
#define NTQUERYDIRECTORYFILEEX		"NtQueryDirectoryFileEx"
#define NTCREATESYMBOLICLINKOBJECT	"NtCreateSymbolicLinkObject"
#define	NTFLUSHBUFFERSFILE			"NtFlushBuffersFile"


// registry
#define NTOPENKEY					"NtOpenKey"
#define NTOPENKEYEX					"NtOpenKeyEx"
#define NTCREATEKEY					"NtCreateKey"
#define NTDELETEVALUEKEY			"NtDeleteValueKey"
#define NTDELETEKEY                 "NtDeleteKey"
#define NTQUERYVALUEKEY				"NtQueryValueKey"
#define NTQUERYKEY					"NtQueryKey"
#define NTQUERYMULTIPLEVALUEKEY		"NtQueryMultipleValueKey"
#define NTENUMERATEKEY				"NtEnumerateKey"
#define NTENUMERATEVALUEKEY			"NtEnumerateValueKey"
#define NTSETVALUEKEY				"NtSetValueKey"
#define NTNOTIFYCHANGEKEY			"NtNotifyChangeKey"
#define NTNOTIFYCHANGEMULTIPLEKEYS	"NtNotifyChangeMultipleKeys"
#define NTFLUSHKEY					"NtFlushKey"
#define NTFREEZEREGISTRY			"NtFreezeRegistry"
#define NTINITIALIZEREGISTRY		"NtInitializeRegistry"
#define NTLOADKEY					"NtLoadKey"
#define NTLOADKEY2					"NtLoadKey2"
#define NTLOADKEYEX					"NtLoadKeyEx"
#define NTSAVEKEY					"NtSaveKey"
#define NTSAVEKEYEX					"NtSaveKeyEx"
#define NTLOCKREGISTRYKEY			"NtLockRegistryKey"
#define NTQUERYOPENSUBKEYS			"NtQueryOpenSubKeys"
#define NTQUERYOPENSUBKEYSEX		"NtQueryOpenSubKeysEx"
#define NTCREATEKEYTRANSACTED		"NtCreateKeyTransacted"
#define NTOPENKEYTRANSACTED			"NtOpenKeyTransacted"
#define NTOPENKEYTRANSACTEDEX		"NtOpenKeyTransactedEx"
#define NTCOMPACTKEYS				"NtCompactKeys"
#define NTCOMPRESSKEY				"NtCompressKey"


// processes and threads
#define NTOPENPROCESS				"NtOpenProcess"
#define NTCREATEUSERPROCESS			"NtCreateUserProcess"
#define NTCREATEPROCESS				"NtCreateProcess"
#define NTCREATEPROCESSEX			"NtCreateProcessEx"
#define NTOPENTHREAD				"NtOpenThread"
#define NTDELAYEXECUTION			"NtDelayExecution"
#define NTSUSPENDPROCESS			"NtSuspendProcess"
#define	NTQUERYVIRTUALMEMORY		"NtQueryVirtualMemory"
#define	NTQUERYINFORMATIONPROCESS	"NtQueryInformationProcess"
constexpr auto ntwritevirtualmemory = "NtWriteVirtualMemory";
constexpr auto ntsetinformationprocess = "NtSetInformationProcess";
constexpr auto ntcontinue = "NtContinue";
constexpr auto ntprotectvirtualmemory = "NtProtectVirtualMemory";
constexpr auto ntsetcontextthread = "NtSetContextThread";

// system related
#define NTQUERYSYSTEMINFORMATION	"NtQuerySystemInformation"
constexpr auto ntloaddriver = "NtLoadDriver";
constexpr auto ntusersystemparametersinfo = "NtUserSystemParametersInfo";
constexpr auto ntraiseharderror = "NtRaiseHardError";

// objects
constexpr auto ntcreatemutant = "NtCreateMutant";
constexpr auto ntopenmutant = "NtOpenMutant";
constexpr auto ntcreatemailslotfile = "NtCreateMailslotFile";
constexpr auto ntcreatesemaphore = "NtCreateSemaphore";
constexpr auto ntopensemaphore = "NtOpenSemaphore";
constexpr auto ntcreateevent = "NtCreateEvent";
constexpr auto ntopenevent = "NtOpenEvent";
constexpr auto ntwaitforsingleobject = "NtWaitForSingleObject";

namespace dr_semu
{
	enum
	{
		SYSCALL_SKIP,
		SYSCALL_CONTINUE
	};

	enum class arch
	{
		x86_32,
		x86_64,
	};

	inline const std::wstring os_path_separator = LR"(\)";
	inline const std::wstring nt_file_prefix = LR"(\??\)";
	inline const std::wstring dos_prefix = LR"(\\?\)";

	namespace shared_variables
	{
		inline concurrent_vector<json> json_concurrent_vector;
		inline concurrent_unordered_set<DWORD> allowed_target_processes;

		inline arch current_app_arch = arch::x86_32;
		inline bool are_children = false;
		inline std::wstring current_vm_name{};
		inline fs::path virtual_filesystem_location{};
		inline std::wstring v_fs_device_form{};
		inline size_t dumb_explorer_pid{};
		inline std::wstring main_launcher_slot_name{};
		inline std::wstring binary_directory{};
		inline std::wstring report_directory_name{};

		// hide Dr.Semu related process from a process listing
		inline std::unordered_set<std::wstring> semu_process_names{};
	} // namespace shared_variables
} // namespace dr_semu

namespace dr_semu::utils
{
	template <typename T>
	T to_upper_string(T input_string)
	{
		std::transform(input_string.begin(), input_string.end(), input_string.begin(), toupper);

		return input_string;
	}

	template <typename T>
	T to_lower_string(T input_string)
	{
		std::transform(input_string.begin(), input_string.end(), input_string.begin(), tolower);

		return input_string;
	}

	inline DWORD get_handle_granted_access(const HANDLE handle)
	{
		DWORD size{};
		OBJECT_BASIC_INFORMATION basic_info{};
		NtQueryObject(handle, ObjectBasicInformation, &basic_info, sizeof(OBJECT_BASIC_INFORMATION), &size);

		return basic_info.GrantedAccess;
	}

	inline bool is_valid_handle(const HANDLE handle)
	{
		DWORD flags{};
		// If the function succeeds, the return value is nonzero.
		return GetHandleInformation(handle, &flags) != 0;
	}

	inline bool get_file_size(const std::wstring& file_path, __out size_t& data_size)
	{
		const std::string file_path_ascii{ file_path.begin(), file_path.end() };
		const auto file_handle = dr_open_file(file_path_ascii.data(), DR_FILE_READ);
		if (file_handle != INVALID_FILE)
		{
			if (dr_file_size(file_handle, reinterpret_cast<uint64*>(&data_size)))
			{
				dr_close_file(file_handle);
				return true;
			}
			dr_close_file(file_handle);
		}

		return false;
	}

	inline bool unicode_string_to_wstring(const PUNICODE_STRING unicode_string, std::wstring& result_string)
	{
		if (nullptr == unicode_string || nullptr == unicode_string->Buffer)
		{
			result_string = {};
			return false;
		}

		const auto number_of_bytes = unicode_string->Length + sizeof(wchar_t); // MAXLENGTH
		const auto number_of_wchar = number_of_bytes / sizeof(wchar_t);

		const std::shared_ptr<wchar_t> object_name_char{ new wchar_t[number_of_wchar] };
		memset(object_name_char.get(), 0, number_of_bytes);

		dr_safe_write(object_name_char.get(), unicode_string->Length, unicode_string->Buffer, nullptr);

		const std::wstring object_name_string{ object_name_char.get(), wcslen(object_name_char.get()) };

		result_string = object_name_string;

		return true;
	}

	inline bool wstring_to_unicode_string(const std::wstring& source_string, PUNICODE_STRING unicode_string)
	{
		const auto length_in_bytes = source_string.length() * sizeof(WCHAR);
		unicode_string->Buffer = new WCHAR[source_string.length() + 1];
		memset(unicode_string->Buffer, 0, length_in_bytes + sizeof(WCHAR));

		memcpy_s(unicode_string->Buffer, length_in_bytes + sizeof(WCHAR), source_string.data(), length_in_bytes);

		unicode_string->Length = length_in_bytes;
		unicode_string->MaximumLength = length_in_bytes + sizeof(WCHAR);

		return true;
	}

	inline size_t find_case_insensitive(std::wstring data, std::wstring to_search, const size_t pos = 0)
	{
		std::transform(data.begin(), data.end(), data.begin(), tolower);
		std::transform(to_search.begin(), to_search.end(), to_search.begin(), tolower);

		return data.find(to_search, pos);
	}

	inline LONGLONG round_up(const LONGLONG num_to_round, const LONGLONG multiple)
	{
		if (num_to_round == 0)
		{
			return multiple;
		}

		if (multiple == 0)
		{
			return num_to_round;
		}

		const auto remainder = num_to_round % multiple;
		if (remainder == 0)
		{
			return num_to_round;
		}

		return num_to_round + multiple - remainder;
	}

	inline std::string read_file_dr(const std::string& file_path)
	{
		const auto file_handle = dr_open_file(file_path.c_str(), DR_FILE_READ);
		if (INVALID_FILE == file_handle)
		{
			return {};
		}

		uint64 file_size{};
		dr_file_size(file_handle, &file_size);

		const std::shared_ptr<char> file_content{ new char[file_size] {} };

		const size_t read_bytes = dr_read_file(file_handle, file_content.get(), file_size);
		if (read_bytes != file_size)
		{
			return {};
		}
		// may contain zeros/null
		return std::string(file_content.get(), file_size);
	}


	// used by hide_fake_explorer()
	inline void rename_ldr(const PVOID base_address, const std::wstring& new_name)
	{
		const auto ptr_peb = NtCurrentTeb()->ProcessEnvironmentBlock;
		const auto ptr_ldr = ptr_peb->Ldr;

		DWORD offset = 0;
		PLIST_ENTRY ptr_module_head{};
		PLIST_ENTRY ptr_module{};

		for (auto i = 0; i < 3; i++)
		{
			switch (i)
			{
			case 0:
				ptr_module_head = ptr_module = &ptr_ldr->InLoadOrderModuleList;
				offset = 0;
				break;

			case 1:
				ptr_module_head = ptr_module = &ptr_ldr->InMemoryOrderModuleList;
				offset = 8;
				break;
			case 2:
				ptr_module_head = ptr_module = &ptr_ldr->InInitializationOrderModuleList;
				offset = 16;
				break;
			default:
				return;
			}

			while (ptr_module->Flink != ptr_module_head)
			{
				ptr_module = ptr_module->Flink;
				const auto ptr_ldr_module = reinterpret_cast<PLDR_MODULE>(PBYTE(ptr_module) - offset);
				if (base_address == ptr_ldr_module->BaseAddress)
				{
					memset(ptr_ldr_module->BaseDllName.Buffer, 0, ptr_ldr_module->BaseDllName.MaximumLength);
					memcpy_s(ptr_ldr_module->BaseDllName.Buffer, ptr_ldr_module->BaseDllName.Length, new_name.c_str(),
						new_name.length() * sizeof(TCHAR));
				}
			}
		}
	}

	inline std::wstring get_name_from_handle(const HANDLE handle, _Out_ bool& is_unnamed)
	{
		is_unnamed = false;
		DWORD name_info_size{};

		auto status = NtQueryObject(handle, ObjectNameInformation, nullptr, 0, &name_info_size);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{

			const std::shared_ptr<BYTE> name_information{ new BYTE[name_info_size] };
			const auto in_size = name_info_size;

			status = NtQueryObject(handle, ObjectNameInformation, name_information.get(), in_size, &name_info_size);
			if (status == STATUS_OBJECT_PATH_INVALID)
			{
				is_unnamed = true;
				return {};
			}

			const auto ptr_name_information = (POBJECT_NAME_INFORMATION)(name_information.get());
			if (ptr_name_information->Name.Buffer == nullptr)
			{
				is_unnamed = true;
				return {};
			}

			std::wstring handle_name(ptr_name_information->Name.Buffer, wcslen(ptr_name_information->Name.Buffer));

			return handle_name;
		}

		return {};
	}

	inline void hide_fake_explorer()
	{
		// hide fake Explorer name: Explorer32/64.exe => Explorer.exe

		const std::wstring explorer_path = L"C:\\Windows\\Explorer.EXE";

		const auto ptr_peb = NtCurrentTeb()->ProcessEnvironmentBlock;
		const auto image_path = ptr_peb->ProcessParameters->ImagePathName;
		// we need command-line in Explorer process to read a mailslot name (change Command Line from the Explorer process)
		//const auto command_line = ptr_peb->ProcessParameters->CommandLine;
		const auto window_title = ptr_peb->ProcessParameters->WindowTitle;

		memset(image_path.Buffer, 0, image_path.MaximumLength);
		//memset(command_line.Buffer, 0, command_line.MaximumLength);
		memset(window_title.Buffer, 0, window_title.MaximumLength);
		memcpy_s(image_path.Buffer, image_path.MaximumLength, explorer_path.c_str(),
			explorer_path.length() * sizeof(TCHAR));
		/*memcpy_s(command_line.Buffer, command_line.MaximumLength, explorer_path.c_str(),
			explorer_path.length() * sizeof(TCHAR));*/
		memcpy_s(window_title.Buffer, window_title.MaximumLength, explorer_path.c_str(),
			explorer_path.length() * sizeof(TCHAR));

		const auto current_directory = ptr_peb->ProcessParameters->CurrentDirectory.DosPath;

		TCHAR system_directory[] = L"C:\\Windows\\System32";
		const auto explorer_current_directory = std::wstring{ system_directory } +L"\\";
		memset(current_directory.Buffer, 0, current_directory.MaximumLength);
		memcpy_s(current_directory.Buffer, current_directory.Length, explorer_current_directory.c_str(),
			explorer_current_directory.length() * sizeof(TCHAR));

		// rename in Ldr
		rename_ldr(reinterpret_cast<PVOID>(GetModuleHandleW(nullptr)), L"Explorer.EXE");
	}
} // namespace dr_semu::utils

namespace dr_semu::syscall
{
	inline std::unordered_map<size_t, std::string> syscall_numbers{};
}

inline bool dr_semu_init()
{
	// get ntdll syscall numbers
	std::vector<std::string> ntdll_syscall_names
	{

#ifndef disable_all_handlers

#ifndef NO_VIRTUAL_FS
		/// filesystem
		NTWRITEFILE,
		//NTCLOSE,
		NTQUERYDIRECTORYFILE,
		NTQUERYDIRECTORYFILEEX,
		NTCREATEDIRECTORYOBJECT,
		NTCREATEFILE,
		NTOPENFILE,
		NTDELETEFILE,
		NTQUERYINFORMATIONFILE,
		NTSETINFORMATIONFILE,
		NTQUERYATTRIBUTESFILE,
		NTCREATESECTION,
		NTMAPVIEWOFSECTION,
		NTQUERYFULLATTRIBUTESFILE,
		NTCREATEPAGINGFILE,
		NTCREATEIOCOMPLETION,
		NTCREATESYMBOLICLINKOBJECT,
#endif // NO_VIRTUAL_FS


#ifndef NO_VIRTUAL_REG
		// registry
		NTOPENKEY,
		NTOPENKEYEX,
		NTCREATEKEY,
		NTDELETEVALUEKEY,
		NTDELETEKEY,
		NTQUERYVALUEKEY,
		NTENUMERATEVALUEKEY,
		NTQUERYKEY,
		NTENUMERATEKEY,
		NTQUERYMULTIPLEVALUEKEY,
		NTSETVALUEKEY,
		NTNOTIFYCHANGEKEY,
		NTNOTIFYCHANGEMULTIPLEKEYS,
		NTCOMPRESSKEY,
		NTCOMPACTKEYS,
		NTOPENKEYTRANSACTED,
		NTOPENKEYTRANSACTEDEX,
		NTCREATEKEYTRANSACTED,
		NTFLUSHKEY,
		NTFREEZEREGISTRY,
		NTINITIALIZEREGISTRY,
		NTLOADKEY,
		NTLOADKEYEX,
		NTLOADKEY2,
		NTSAVEKEY,
		NTSAVEKEYEX,
		NTLOCKREGISTRYKEY,
		NTQUERYOPENSUBKEYS,
		NTQUERYOPENSUBKEYSEX,
#endif

		// processes and threads
		NTOPENPROCESS,
		NTCREATEUSERPROCESS,
		NTCREATEPROCESS,
		NTCREATEPROCESSEX,
		NTSUSPENDPROCESS,
		////NTOPENTHREAD,
		////NTDELAYEXECUTION,
		NTQUERYVIRTUALMEMORY,
		NTQUERYINFORMATIONPROCESS,
		ntwritevirtualmemory,
		ntcontinue,
		ntprotectvirtualmemory,
		ntsetcontextthread,

		// system related
		NTQUERYSYSTEMINFORMATION,
		ntloaddriver,
		ntraiseharderror,
		ntsetinformationprocess,

		// objects
		ntcreatemutant,
		ntopenmutant,
		ntcreatemailslotfile,
		ntcreatesemaphore,
		ntopensemaphore,
		ntcreateevent,
		ntopenevent,
		ntwaitforsingleobject,

#endif
	};

	const auto ntdll_module = dr_lookup_module_by_name("ntdll.dll");
	if (ntdll_module == nullptr)
	{
		dr_printf("[dr_semu_init] failed to get NTDLL module\n");
		return false;
	}
	for (const auto& function_name : ntdll_syscall_names)
	{
		const auto entry = reinterpret_cast<PBYTE>(dr_get_proc_address(
			ntdll_module->handle, function_name.c_str()));
		if (entry == nullptr)
		{
			dr_printf("[dr_semu_init] failed to find %s function\n", function_name.c_str());
			continue;
		}
		const auto syscall_number = drmgr_decode_sysnum_from_wrapper(entry);
		if (syscall_number == -1)
		{
			dr_printf("Failed to get sysnum for %s (ntdll.dll)", function_name.c_str());
			continue;
		}
		dr_semu::syscall::syscall_numbers[syscall_number] = function_name;
	}
	dr_free_module_data(ntdll_module);

	// win32u syscalls
	std::vector<std::string> win32_syscall_names
	{
#ifndef disable_all_handlers

		// system related
		ntusersystemparametersinfo,

#endif
	};

	const auto win32_module = dr_lookup_module_by_name("win32u.dll");
	if (win32_module == nullptr)
	{
		dr_printf("[dr_semu_init] failed to get win32u module\n");
		//return false;
		return true;
	}
	for (const auto& function_name : win32_syscall_names)
	{
		const auto entry = reinterpret_cast<PBYTE>(dr_get_proc_address(
			win32_module->handle, function_name.c_str()));
		if (entry == nullptr)
		{
			dr_printf("[dr_semu_init] failed to find %s function\n", function_name.c_str());
			continue;
		}
		const auto syscall_number = drmgr_decode_sysnum_from_wrapper(entry);
		if (syscall_number == -1)
		{
			dr_printf("Failed to get sysnum for %s (win32u.dll)\n", function_name.c_str());
			continue;
		}
		dr_semu::syscall::syscall_numbers[syscall_number] = function_name;
	}
	dr_free_module_data(win32_module);

	return true;
}
