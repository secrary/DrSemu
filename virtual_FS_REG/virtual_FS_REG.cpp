#include "delete.hpp" // I don't know why it fails if we include it after "includes.h"
#include "includes.h"

#include "../DrSemu/shared.hpp"

#include "virtual_reg.h"


bool enable_privileges()
{
	// TODO (lasha): enable only necessary privileges
	BOOLEAN prev{};
	RtlAdjustPrivilege(SE_SYSTEM_PROFILE_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_SECURITY_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_CREATE_TOKEN_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_MACHINE_ACCOUNT_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_TAKE_OWNERSHIP_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_CREATE_PERMANENT_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &prev);
	RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &prev);

	return true;
}

void generate_security_desciptor_for_files()
{
	// generate sd
	const auto sd_file_path = fs::temp_directory_path().wstring() + L"rndm_file.fs";
	const auto h_file = CreateFileW(sd_file_path.c_str(), GENERIC_ALL, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0,
	                                nullptr);
	if (h_file == INVALID_HANDLE_VALUE)
	{
		const auto last_error = GetLastError();
		printf("[CreateFile] failed: %ls last_error: 0x%x\n", sd_file_path.c_str(), last_error);
		ExitProcess(-3);
	}
	CloseHandle(h_file);
	permissions(sd_file_path, fs::perms::all, fs::perm_options::add);

	virtual_fs::fs_descriptor.len = {};
	const auto requested_information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
		SACL_SECURITY_INFORMATION;
	GetFileSecurity(sd_file_path.data(), requested_information, nullptr, 0, &virtual_fs::fs_descriptor.len);

	if (virtual_fs::fs_descriptor.len == 0)
	{
		const auto last_err = GetLastError();
		// if (last_err != ERROR_FILE_NOT_FOUND)
		printf("ProjFS: GetFileSecurity failed, err: %lu\nPath: %ls\n\n", last_err, sd_file_path.c_str());
		ExitProcess(-1);
	}

	const std::shared_ptr<byte> ptr_fs(static_cast<byte*>(
		                                   calloc(1, virtual_fs::fs_descriptor.len)),
	                                   free);

	virtual_fs::fs_descriptor.ptr_sd = ptr_fs;

	if (0 == GetFileSecurity(sd_file_path.c_str(), requested_information,
	                         virtual_fs::fs_descriptor.ptr_sd.get(),
	                         virtual_fs::fs_descriptor.len, &virtual_fs::fs_descriptor.len))
	{
		const auto last_err = GetLastError();
		printf("ProjFS: GetFileSecurity failed, err: %lu\nPath: %ls\n\n", last_err, sd_file_path.c_str());
		ExitProcess(-2);
	}
}

std::wstring get_temp_dir()
{
	std::error_code err_code{};
	const auto temp_dir_shorten = fs::temp_directory_path(err_code);

	auto chars_size = GetLongPathName(temp_dir_shorten.c_str(), nullptr, 0);
	const std::shared_ptr<TCHAR> long_path{new TCHAR[chars_size]{}};
	chars_size = GetLongPathName(temp_dir_shorten.c_str(), long_path.get(), chars_size);

	return std::wstring(long_path.get(), chars_size);
}

int __cdecl wmain(const int argc, const WCHAR** argv)
{
	//enable_privileges();
	//const registry::virtual_registry virtual_regx(L"dr_semu_x");
	//if (virtual_regx.is_loaded)
	//{
	//	spdlog::info(L"virtual_REG is running at virtualization root [{}]",
	//		virtual_regx.virtual_reg_root.c_str());
	//}
	//else
	//{
	//	spdlog::critical("Failed to start virtual REG");
	//}
	//return 0x123;
	///
	spdlog::info("Virtual Filesystem & Registry");
	if (argc < 3)
	{
		spdlog::error("[!] not enough arguments");
		MessageBox(nullptr, nullptr, nullptr, 0);
		return -1;
	}
	auto reset_reg = false;
	if (std::wstring reg_arg(argv[2]); reg_arg == L"reset_cache")
	{
		reset_reg = true;
	}

	const std::wstring vm_index_string = argv[3];
	const auto current_vm_prefix = L"dr_semu_" + vm_index_string;
	std::error_code err_code{};

	/// pipe to commicate with a launcher
	std::wstring pipe_name{};
	if (argc > 1)
	{
		pipe_name = argv[1];
	}

	//spdlog::info("Connecting to a launcher...");

	dr_semu::shared::pipe launcher_pipe(pipe_name, false);
	if (!launcher_pipe.is_valid())
	{
		printf("Failed to connect pipe. last err: 0x%x\npipe_name: %ls\n", GetLastError(),
		       launcher_pipe.pipe_name.c_str()); // log to a file
		MessageBox(nullptr, L"Failed to connect pipe", L"", 0);
		return -1;
	}

	spdlog::info("Conntected to a Launcher");

	const auto vm_directory_path = get_temp_dir() + current_vm_prefix;
	if (fs::exists(vm_directory_path))
	{
		const auto is_success = delete_directory(vm_directory_path);
		if (is_success)
		{
			spdlog::info("vFS deleted [DONE]");
		}
		else
		{
			spdlog::error("vFS deleting failed");
			MessageBox(nullptr, nullptr, nullptr, 0);
		}
	}

	auto fs_options = PRJ_STARTVIRTUALIZING_OPTIONS();

	fs_options.ConcurrentThreadCount = 1;
	fs_options.PoolThreadCount = 1;

	enable_privileges();

#ifndef NO_VIRTUAL_REG
	// create virtual registry
	const registry::virtual_registry virtual_reg(current_vm_prefix);
	if (virtual_reg.is_loaded)
	{
		spdlog::info(L"virtual_REG is running at virtualization root [{}]",
		             virtual_reg.virtual_reg_root.c_str());
	}
	else
	{
		spdlog::critical("Failed to start virtual REG");
	}
#endif
	// generate sd with all permissions
	generate_security_desciptor_for_files();

	// Start the provider using the options we set up.
	virtual_fs::fs_provider fs_provider;

	auto hr = fs_provider.Start(vm_directory_path.c_str(), &fs_options);
	if (FAILED(hr))
	{
		spdlog::critical(L"Failed to start virtualization instance: {:x}\npath: {}", hr, vm_directory_path.c_str());
		MessageBox(nullptr, nullptr, nullptr, 0);
		return -1;
	}

	/// send status to a launcher
	std::wstring ok_msg = L"OK";
	launcher_pipe.write_pipe(ok_msg);

	spdlog::info("virtual_FS_REG is running");
	spdlog::info(L"FS: {}", vm_directory_path);
#ifndef NO_VIRTUAL_REG
	spdlog::info(L"REG: {}", virtual_reg.virtual_reg_root);
#endif

	//spdlog::info("Press Enter to stop the fs_provider and reg_provider...");
	//getchar();

	/// waiting
	std::wstring read_content{};
	launcher_pipe.read_pipe(read_content);
	if (read_content != L"END")
	{
		spdlog::error(L"The command is not \"END\", command: {}", read_content);
	}
	else
	{
		spdlog::info("EXITING...");
	}


	fs_provider.Stop();

	const auto is_success = delete_directory(vm_directory_path);
	if (is_success)
	{
		spdlog::info("vFS deleted [DONE]");
	}
	else
	{
		spdlog::error("vFS deleting failed");
	}

	//MessageBox(nullptr, L"END! virtual FS/REG", L"FS/REG", 0);
	return 0;
}
