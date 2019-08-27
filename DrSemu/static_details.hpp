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

		const auto pe_binary = pe_parse(file_path.c_str());
		if (pe_binary == nullptr)
		{
			dr_printf("Failed to get a static information\nfile path: %s\n", file_path.c_str());
			return false;
		}

		if (pe_binary->header.machine == 0x14c) // IMAGE_FILE_MACHINE_I386
		{
			app_arch = arch::x86_32;
		}
		else
		{
			app_arch = arch::x86_64;
		}
		const auto is_x86 = app_arch == arch::x86_32;

		uint64_t entry_point = pe_binary->optional_header.addressof_entrypoint;


		// CryptAcquireContext crashes DR => use third-party C hashing library
		const auto file_content = utils::read_file_dr(file_path);
		const auto file_sha2_ascii = digestpp::sha256().absorb(file_content).hexdigest();
		const std::wstring file_sha2(file_sha2_ascii.begin(), file_sha2_ascii.end());


		const auto report_path = shared_variables::binary_directory + shared_variables::report_directory_name + L"\\" +
			file_sha2 + L".json";
		if (fs::exists(report_path, ec))
		{
			return true;
		}
		const std::string report_path_string(report_path.begin(), report_path.end());

		/// create json
		json static_info;
		static_info["generic"] = {
			{
				"name",
				pe_binary->name
			},
			{
				"is_x86",
				is_x86
			},
			{
				"image_base",
				pe_binary->optional_header.imagebase
			},
		};
		static_info["dos_header"] = {
			{
				"magic",
				pe_binary->optional_header.magic
			},
			{
				"checksum",
				pe_binary->optional_header.checksum
			},
		};


		const auto sections = pe_binary->sections;
		std::vector<std::string> vec_sections{};
		for (auto index = 0; sections[index] != nullptr; index++)
		{
			vec_sections.emplace_back(sections[index]->name);
		}
		static_info["sections"] = vec_sections;

		const auto imports = pe_binary->imports;
		if (imports)
		{
			for (auto index = 0; imports[index] != nullptr; index++)
			{
				const std::string import_name(imports[index]->name);
				std::vector<std::string> function_names{};

				if (imports[index]->entries)
				{
					for (auto entry_index = 0; imports[index]->entries[entry_index] != nullptr; entry_index++)
					{
						if (!imports[index]->entries[entry_index]->is_ordinal)
						{
							const std::string imported_function(imports[index]->entries[entry_index]->name);
							if (!imported_function.empty())
							{
								function_names.emplace_back(imported_function);
							}
						}
					}
				}
				static_info["imports"][import_name] = function_names;
			}
		}

		const auto out_json_file = dr_open_file(report_path_string.c_str(), DR_FILE_WRITE_OVERWRITE);
		if (INVALID_FILE == out_json_file)
		{
			dr_printf("[get_static_info_and_arch] failed to open json file: %s\n", report_path_string.c_str());
			return false;
		}
		const auto json_str = static_info.dump();
		dr_write_file(out_json_file, json_str.data(), json_str.length());
		dr_close_file(out_json_file);

		pe_binary_destroy(pe_binary);
		return true;
	}
} // namespace dr_semu::static_info
