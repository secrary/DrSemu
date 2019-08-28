#pragma once

#include "digestpp.hpp"

namespace dr_semu::static_info
{
	// DR clients cannot handle C++ exceptions, so use noexcept variants if possible
	inline std::error_code ec;

	inline bool get_static_info_and_arch(_In_ const std::string& file_path, _Out_ arch& app_arch)
	{
		if (!fs::exists(file_path, ec))
		{
			dr_printf("[get_static_info_and_arch] invalid file path: %s\n", file_path.c_str());
			return false;
		}

		const auto pe_binary = peparse::ParsePEFromFile(file_path.c_str());
		if (pe_binary == nullptr)
		{
			dr_printf("Failed to get a static information\nfile path: %s\n", file_path.c_str());
			dr_printf("Error: 0x%lx (%s)\nLocation: %s\n", peparse::GetPEErr(), peparse::GetPEErrString().c_str(),
				peparse::GetPEErrLoc().c_str());
			return false;
		}

		if (pe_binary->peHeader.nt.FileHeader.Machine == 0x14c) // IMAGE_FILE_MACHINE_I386
		{
			app_arch = arch::x86_32;
		}
		else
		{
			app_arch = arch::x86_64;
		}
		const auto is_x86 = app_arch == arch::x86_32;

		const auto pe_optional_header32 = pe_binary->peHeader.nt.OptionalHeader;
		const auto pe_optional_header64 = pe_binary->peHeader.nt.OptionalHeader64;

		uint64_t entry_point = 0;
		if (is_x86)
		{
			entry_point = pe_optional_header32.AddressOfEntryPoint;
		}
		else
		{
			entry_point = pe_optional_header64.AddressOfEntryPoint;
		}

		// CryptAcquireContext crashes DR => use third-party C hashing library
		const auto file_content = utils::read_file_dr(file_path);
		const auto file_sha2_ascii = digestpp::sha256().absorb(file_content).hexdigest();
		const std::wstring file_sha2(file_sha2_ascii.begin(), file_sha2_ascii.end());


		const auto report_path = shared_variables::binary_directory + shared_variables::report_directory_name + L"\\" +
			file_sha2 + L".json";
		if (fs::exists(report_path, ec))
		{
			peparse::DestructParsedPE(pe_binary);
			return true;
		}
		const std::string report_path_string(report_path.begin(), report_path.end());

		/// create json
		json static_info;
		static_info["generic"] = {
			{
				"is_x86",
				is_x86
			},
			{
				"image_base",
				is_x86 ? pe_binary->peHeader.nt.OptionalHeader.ImageBase : pe_binary->peHeader.nt.OptionalHeader64.ImageBase
			},
		};
		static_info["dos_header"] = {
			{
				"magic",
				is_x86 ? pe_binary->peHeader.nt.OptionalHeader.Magic : pe_binary->peHeader.nt.OptionalHeader64.Magic
			},
			{
				"checksum",
				is_x86 ? pe_binary->peHeader.nt.OptionalHeader.CheckSum : pe_binary->peHeader.nt.OptionalHeader64.CheckSum
			},
		};


		
		std::vector<std::string> vec_sections{};
		//static_info["sections"] = vec_sections;


		const auto out_json_file = dr_open_file(report_path_string.c_str(), DR_FILE_WRITE_OVERWRITE);
		if (INVALID_FILE == out_json_file)
		{
			dr_printf("[get_static_info_and_arch] failed to open json file: %s\n", report_path_string.c_str());
			peparse::DestructParsedPE(pe_binary);
			return false;
		}
		const auto json_str = static_info.dump();
		dr_write_file(out_json_file, json_str.data(), json_str.length());
		dr_close_file(out_json_file);

		peparse::DestructParsedPE(pe_binary);

		return true;
	}
} // namespace dr_semu::static_info
