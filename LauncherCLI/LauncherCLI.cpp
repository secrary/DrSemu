#define NOMINMAX

// if not before Windows.h => fails
#include <parser-library/parse.h>

#include <Windows.h>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <thread>

#include "utils.hpp"

#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "cxxopts.hpp"
#include "nlohmann/json.hpp"
#include <digestpp.hpp>

#include "../DrSemu/shared.hpp"



const std::wstring virtual_fs_reg = L"virtual_FS_REG.exe";

inline std::wstring get_current_location()
{
	TCHAR cur_loc[MAX_PATH]{};
	const auto result_size = GetModuleFileName(nullptr, cur_loc, MAX_PATH);

	const std::wstring current_location(cur_loc, result_size);
	return fs::path(current_location).remove_filename().wstring();
}

bool run_app_under_dr_semu(
	const std::wstring& target_application,
	const std::wstring& target_command_line,
	const std::wstring& vm_index_string,
	const std::wstring& binaries_location,
	const std::wstring& temp_dir,
	DWORD explorer_pid,
	const std::wstring& report_directory_name,
	const std::wstring& main_mailslot_name,
	DWORD timeout_seconds
);

std::wstring get_temp_dir()
{
	std::error_code err_code{};
	const auto temp_dir_shorten = fs::temp_directory_path(err_code);

	auto chars_size = GetLongPathName(temp_dir_shorten.c_str(), nullptr, 0);
	const std::shared_ptr<TCHAR> long_path{ new TCHAR[chars_size]{} };
	chars_size = GetLongPathName(temp_dir_shorten.c_str(), long_path.get(), chars_size);

	return std::wstring(long_path.get(), chars_size);
}

int main(int argc, char* argv[])
{
	std::string file_path_ascii{};
	cxxopts::Options options("Dr.Semu LauncherCLI", "CLI Launcher for Dr.Semu");
	options.add_options()
		("t,target", "File or Directory path", cxxopts::value<std::string>());
	try
	{
		auto cmd_result = options.parse(argc, argv);
		file_path_ascii = cmd_result["target"].as<std::string>();
	}
	catch (...)
	{
		std::cout << options.help();
		return -1;
	}

	if (!fs::exists(file_path_ascii))
	{
		spdlog::critical("No such file/directory: {}\n", file_path_ascii);
		return -1;
	}

	std::wstring target_application{};
	std::wstring target_directory{};
	if (fs::is_regular_file(file_path_ascii))
	{
		if (!file_path_ascii.ends_with(".exe"))
		{
			spdlog::critical("Invalid file extension: {}\n", file_path_ascii);
			return -1;
		}
		target_application = std::wstring(file_path_ascii.begin(), file_path_ascii.end());
	}
	else if (fs::is_directory(file_path_ascii))
	{
		target_directory = std::wstring(file_path_ascii.begin(), file_path_ascii.end());
	}
	else
	{
		spdlog::critical("[Dr.Semu] Invalid target path: {}\n", file_path_ascii);
	}

	spdlog::flush_every(std::chrono::seconds(3));
	spdlog::info("LauncherCLI for Dr.Semu");

	/// UNCOMMENT FOR TESTING !!!
	//target_application =
	//	// x64
	//	//LR"(C:\windows\system32\cmd.exe)";
	//	// x86
	//	LR"(C:\Windows\SysWOW64\cmd.exe)";

	const std::wstring target_arguments = LR"()";

	const auto binaries_location = get_current_location();
	if (!SetCurrentDirectory(binaries_location.c_str()))
	{
		spdlog::critical("SetCurrentDirectory() failed, error {}", GetLastError());
		return -1;
	}

	// dr.clients fail to get long_path while calling GetLongPathName, so provide it from command arguments
	const auto temp_dir = get_temp_dir();

	//volatile size_t vm_index = 1;
	//if (argc > 1)
	//{
	//	vm_index = std::stoi(argv[1]);
	//}

	std::vector<std::wstring> target_directory_files{};
	if (!target_application.empty())
	{
		target_directory_files.emplace_back(target_application);
	}
	else if (!target_directory.empty())
	{
		for (const auto& file_path : fs::directory_iterator(target_directory))
		{
			const auto target_file_path = file_path.path().wstring();
			if (fs::is_regular_file(target_file_path) && target_file_path.ends_with(L".exe"))
			{
				target_directory_files.emplace_back(target_file_path);
			}
		}
	}
	else
	{
		spdlog::critical("[Dr.Semu] File/Directory path is empty\n");
		return -1;
	}

	auto vm_thread_function =
		[&](std::wstring target_application, size_t vm_index)
	{
		// to receive process creation/termination infos and track them
		const auto main_mailslot_name = launchercli::get_true_random_string(20);
		dr_semu::shared::slot main_mailslot(main_mailslot_name);
		if (!main_mailslot.is_valid())
		{
			spdlog::critical(L"[VM_{}] Failed to create a slot. slot name: {}", vm_index, main_mailslot_name);
			return;
		}

		// virtual_fs and virtual_reg
		const auto full_path_virtual_fs_reg = binaries_location + virtual_fs_reg;
		if (!fs::exists(full_path_virtual_fs_reg))
		{
			spdlog::critical(L"[VM_{}] Failed to find virtual FS/REG executable. path: {}", vm_index, full_path_virtual_fs_reg);
			return;
		}

		const auto pipe_name = launchercli::get_true_random_string(15);
		dr_semu::shared::pipe virtual_fs_pipe(pipe_name);
		if (!virtual_fs_pipe.is_valid())
		{
			spdlog::critical(L"[VM_{}] Failed to init a pipe.\npipe_name: {}\nerr: {}\n", vm_index, pipe_name, GetLastError());
			return;
		}

		const auto vm_index_string = std::to_wstring(vm_index);
		const auto fs_reg_params = (pipe_name + L" " + L"use_cache" + L" " + vm_index_string);
		// reset_cache if you want to cache new reg
		SHELLEXECUTEINFO exec_info{};
		exec_info.cbSize = sizeof(exec_info);
		exec_info.hwnd = nullptr;
		exec_info.lpVerb = L"runas";
		exec_info.lpFile = full_path_virtual_fs_reg.c_str();
		exec_info.lpParameters = fs_reg_params.c_str();
		exec_info.nShow = SW_SHOW; // SW_HIDE;

		if (!ShellExecuteEx(&exec_info))
		{
			spdlog::error(L"[VM_{}] Failed to execute virtual_fs_reg\npath: {}\n", vm_index, full_path_virtual_fs_reg);
			return;
		}
		spdlog::info("[VM_{}] Connecting to virtual FS/REG...", vm_index);

		if (!virtual_fs_pipe.wait_for_client())
		{
			spdlog::error(L"[VM_{}] Failed to make pipe connection {}.\npipe_name: {}\npipe_handle {}\n", vm_index, GetLastError(),
				virtual_fs_pipe.pipe_name, virtual_fs_pipe.pipe_handle);
			return;
		}
		spdlog::info("[VM_{}] Connected to virtual FS/REG!", vm_index);

		std::wstring read_content{};
		if (virtual_fs_pipe.read_pipe(read_content))
		{
			if (read_content != L"OK")
			{
				spdlog::error(L"[VM_{}] virtual_fs_reg failed. command: {}\n", vm_index, read_content);
				// terminate the process
				return;
			}
			spdlog::info("[VM_{}] virtual FS/REG: SUCCESS", vm_index);
		}
		else
		{
			spdlog::critical("[VM_{}] Pipe communication with FS/REG failed. pipe handle: {}", vm_index, virtual_fs_pipe.pipe_handle);
			return;
		}
		/// virtual_reg and virtual_reg is ready

		const auto report_directory_name = launchercli::get_true_random_string(15);
		const auto report_directory = binaries_location + report_directory_name;
		if (fs::exists(report_directory))
		{
			fs::remove_all(report_directory);
		}
		fs::create_directories(report_directory);

		/// launch fake explorer.exe
		const auto dumb_explorer_path = binaries_location + L"explorer64.exe";

		DWORD explorer_pid{};
		if (!fs::exists(dumb_explorer_path))
		{
			spdlog::error(L"[VM_{}] Failed to locate a dumb explorer.exe. path: {}", vm_index, dumb_explorer_path);
			return;
		}
		const auto explorer_mailslot_name = launchercli::get_true_random_string(20);
		dr_semu::shared::slot explorer_mailslot(explorer_mailslot_name);
		if (!explorer_mailslot.is_valid())
		{
			spdlog::critical(L"[VM_{}] Failed to create a slot[ExplorerSlot]. slot name: {}", vm_index, explorer_mailslot_name);
			return;
		}
		// we send "END" command when all target processes die
		const auto explorer_event_name = launchercli::get_true_random_string(15);
		const auto explorer_kill_event = CreateEvent(nullptr, FALSE, FALSE, explorer_event_name.c_str());
		if (explorer_kill_event == nullptr)
		{
			spdlog::critical(L"[VM_{}] Failed to create a event [ExplorerKiller]. event name: {}; err: {}", vm_index, explorer_event_name,
				GetLastError());
			return;
		}
		if (!run_app_under_dr_semu(
			dumb_explorer_path,
			explorer_event_name,
			vm_index_string,
			binaries_location,
			temp_dir,
			0, // get current_pid from Dr.Semu
			report_directory_name,
			explorer_mailslot_name,
			0 // without monitoring thread
		))
		{
			spdlog::error("[VM_{}] Failed to execute fake Explorer under Dr.Semu", vm_index);
			return;
		}
		std::wstring from_explorer{};
		explorer_mailslot.read_slot(from_explorer);
		std::vector<std::wstring> explorer_data_vec{};
		launchercli::split_wide_string(from_explorer, explorer_data_vec);
		if (explorer_data_vec.size() != 2)
		{
			spdlog::error(L"[VM_{}] Invalid data from a client [explorer]: {}", vm_index, from_explorer);
		}
		if (explorer_data_vec[0] == L"add")
		{
			explorer_pid = std::stoi(explorer_data_vec[1]);
		}
		else
		{
			spdlog::error(L"[VM_{}] Invalid command from a fake Explorer. command: {}", vm_index, from_explorer);
			return;
		}
		spdlog::info("[VM_{}] Fake Explorer is under Dr.Semu. PID: {}", vm_index, explorer_pid);

		// get a file hash
		std::string image_path_ascii(target_application.begin(), target_application.end());
		const auto file_content = launchercli::read_file_content(image_path_ascii);
		const auto file_sha2_ascii = digestpp::sha256().absorb(file_content).hexdigest();

		/// launch target application under Dr.Semu
		const auto timeout_seconds = 30;
		if (!run_app_under_dr_semu(
			target_application,
			target_arguments,
			vm_index_string,
			binaries_location,
			temp_dir,
			explorer_pid,
			report_directory_name,
			main_mailslot_name,
			timeout_seconds
		))
		{
			spdlog::error("[VM_{}] Failed to execute the application under Dr.Semu", vm_index);
			return;
		}

		size_t starter_proc_id = 0;

		/// loop 
		std::wstring client_data{};
		std::unordered_set<DWORD> pids{};
		do
		{
			main_mailslot.read_slot(client_data);
			std::vector<std::wstring> client_data_vec{};
			launchercli::split_wide_string(client_data, client_data_vec);

			if (client_data_vec.size() != 2)
			{
				spdlog::error(L"[VM_{}] invalid data from a client: {}\n", vm_index, client_data.c_str());
			}

			else if (client_data_vec[0] == L"add")
			{
				const auto pid = std::stoi(client_data_vec[1]);
				if (starter_proc_id == 0)
				{
					starter_proc_id = pid;
					spdlog::info("[VM_{}] Starter PID: {}", vm_index, starter_proc_id);
				}
				pids.insert(pid);
			}
			else if (client_data_vec[0] == L"remove")
			{
				pids.erase(std::stoi(client_data_vec[1]));
			}

			if (!pids.empty())
			{
				spdlog::info("[VM_{}] Running processes:", vm_index);
				for (auto pid : pids)
				{
					printf("\tPID: %lu\n", pid);
				}
			}
		} while (!pids.empty());

		// kill the fake explorer process
		if (SetEvent(explorer_kill_event) == 0)
		{
			spdlog::error("[VM_{}] Failed to terminate the fake Explorer process. [PID - {}]", vm_index, explorer_pid);
		}
		else
		{
			spdlog::info("[VM_{}] Fake Explorer [PID - {}] terminated", vm_index, explorer_pid);
		}
		CloseHandle(explorer_kill_event);
		explorer_mailslot.read_slot(from_explorer); // wait remove command from the fake Explorer

		// create reports

		nlohmann::json starter_json;
		starter_json["image_path"] = image_path_ascii.c_str();
		starter_json["starter_pid"] = starter_proc_id;
		starter_json["explorer_pid"] = explorer_pid;
		starter_json["sha_256"] = file_sha2_ascii;

		const auto starter_file = report_directory + L"\\" + L"starter.json";
		std::error_code error_code{};
		if (fs::exists(starter_file, error_code))
		{
			fs::remove(starter_file, error_code);
		}
		const auto json_string = starter_json.dump();
		launchercli::write_string_to_file(starter_file, json_string, json_string.length());

		/// end_command to virtual_fs_reg
		spdlog::info("[VM_{}] Sending terminating command to FS/REG", vm_index);
		const auto fs_result = virtual_fs_pipe.write_pipe(L"END");


		/// current execution reports (main executable and all other processes created by the executable)
		spdlog::info(L"[VM_{}] Reports: {}", vm_index, report_directory);

		/// run detections
		spdlog::info("[VM_{}] Scanning...", vm_index);
		const auto scan_slot_name = launchercli::get_true_random_string(15);
		dr_semu::shared::slot scan_slot(scan_slot_name);
		if (!scan_slot.is_valid())
		{
			spdlog::error("[VM_{}] Failed to create a slot [scan slot]\n", vm_index);
			return;
		}
		const auto run_detections_exe = binaries_location + L"run_detections.exe";
		if (!fs::exists(run_detections_exe))
		{
			spdlog::error(L"[VM_{}] Failed to find run_detections\npath: {}\n", vm_index, run_detections_exe);
			return;
		}
		STARTUPINFO run_detections_sa{ sizeof(STARTUPINFO) };
		PROCESS_INFORMATION run_detections_pi{};
		auto run_detections_command_line =
			L"\"" + report_directory + L"\"" +
			L" \"" + scan_slot_name + L"\"";
		if (!CreateProcess(run_detections_exe.c_str(), run_detections_command_line.data(), nullptr, nullptr, FALSE,
			0, /*CREATE_NEW_CONSOLE,*/
			nullptr, nullptr, &run_detections_sa,
			&run_detections_pi))
		{
			spdlog::error("[VM_{}] Failed to create a dumb explorer process\n", vm_index);
			return;
		}
		CloseHandle(run_detections_pi.hProcess);
		CloseHandle(run_detections_pi.hThread);
		std::wstring scan_result{};
		scan_slot.read_slot(scan_result);
		if (scan_result == dr_semu::shared::constants::FAILED)
		{
			spdlog::error("[VM_{}] run_detections failed", vm_index);
			MessageBox(nullptr, L"run_detections failed", nullptr, 0);
			return;
		}

		spdlog::critical(L"Verdict: {}", scan_result);

		MessageBox(nullptr, L"EOF", L"LauncherCLI for Dr.Semu", 0);

		/// delete report directory
		fs::remove_all(report_directory, error_code);

		return;
	};

	std::vector<std::thread> threads{};
	size_t vm_index = 1;
	for (const auto target_application : target_directory_files)
	{
		threads.emplace_back(vm_thread_function, target_application, vm_index);
		vm_index++;
	}

	std::for_each(threads.begin(), threads.end(), [](auto& thread_object)
		{
			thread_object.join();
		});

	return 0;
}

bool get_arch(const std::wstring& file_path, launchercli::arch& arch)
{
	const std::string file_path_ascii(file_path.begin(), file_path.end());
	const auto pe_binary = peparse::ParsePEFromFile(file_path_ascii.c_str());
	if (pe_binary == nullptr)
	{
		spdlog::critical(L"peparse::ParsePEFromFile failed. file path: {}", file_path);
		return false;
	}

	if (pe_binary->peHeader.nt.FileHeader.Machine == 0x14c)
	{
		arch = launchercli::arch::x86_32;
	}
	else
	{
		arch = launchercli::arch::x86_64;
	}
	DestructParsedPE(pe_binary);

	return true;
}

bool run_app_under_dr_semu(
	const std::wstring& target_application,
	const std::wstring& target_command_line,
	const std::wstring& vm_index_string,
	const std::wstring& binaries_location,
	const std::wstring& temp_dir,
	const DWORD explorer_pid,
	const std::wstring& report_directory_name,
	const std::wstring& main_mailslot_name,
	const DWORD timeout_seconds
)
{
	auto arch = launchercli::arch::x86_32;
	const auto is_valid = get_arch(target_application, arch);
	if (!is_valid)
	{
		spdlog::error("is_x86_file failed");
		return false;
	}

	const auto is_admin_required = launchercli::is_administrator_required(target_application);

	auto client_dll_path = binaries_location + L"bin64\\" + L"drsemu_x64.dll";
	if (arch == launchercli::arch::x86_32)
	{
		client_dll_path = binaries_location + L"bin32\\" + L"drsemu_x86.dll";
	}

	if (!fs::exists(client_dll_path))
	{
		spdlog::error(L"Failed to locate DR client: {}", client_dll_path);
		return false;
	}

	std::wstring dr_run_path = binaries_location + L"dynamorio\\bin64\\drrun.exe";
	if (arch == launchercli::arch::x86_32)
	{
		dr_run_path = binaries_location + L"dynamorio\\bin32\\drrun.exe";
	}
	if (!fs::exists(dr_run_path))
	{
		spdlog::error(L"Failed to locate drrun.exe: {}", dr_run_path);
		return false;
	}

	const auto client_arguments =
		L"-vm " + vm_index_string +
		L" " + L"-pid " + std::to_wstring(explorer_pid) +
		L" " + L"-bin " + binaries_location +
		L" " + L"-dir " + temp_dir +
		L" " + L"-report " + report_directory_name +
		L" " + L"-main_slot " + main_mailslot_name +
		L" " + L"-timeout " + std::to_wstring(timeout_seconds);

	const auto dr_run_arguments =
		std::wstring{ LR"(-client ")" } +
		client_dll_path +
		LR"(" -- ")" +
		client_arguments +
		LR"(" ")" +
		target_application + LR"(" )" +
		target_command_line;

	SHELLEXECUTEINFO exec_info_client{};
	exec_info_client.cbSize = sizeof(exec_info_client);
	exec_info_client.hwnd = nullptr;
	exec_info_client.lpVerb = is_admin_required ? L"runas" : nullptr;
	exec_info_client.lpFile = dr_run_path.c_str();
	exec_info_client.lpParameters = dr_run_arguments.c_str();
	exec_info_client.nShow = SW_SHOW; // SW_HIDE;

	if (!ShellExecuteEx(&exec_info_client))
	{
		spdlog::error(L"Failed to execute virtual_fs_reg. path: {}", dr_run_path);
		return false;
	}


	return true;
}
