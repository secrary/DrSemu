#pragma once

#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <random>

namespace launchercli
{
	enum class arch
	{
		x86_32,
		x86_64,
		OTHER
	};

	// http://www.martinbroadhurst.com/how-to-split-a-string-in-c.html
	template <typename T>
	void split_wide_string(__in const std::wstring& str, __out T& container)
	{
		using wistringstream = std::basic_istringstream<wchar_t>;
		std::wistringstream iss{str};
		std::copy(std::istream_iterator<std::wstring, wchar_t>(iss),
		          std::istream_iterator<std::wstring, wchar_t>(),
		          std::back_inserter(container));
	}

	std::wstring get_true_random_string(const size_t size)
	{
		/// https://www.fluentcpp.com/2019/05/24/how-to-fill-a-cpp-collection-with-random-values/
		const auto random_numbers = [](int low, int high)
		{
			auto random_function = [distribution_ = std::uniform_int_distribution<int>(low, high),
					random_engine_ = std::mt19937{std::random_device{}()}]() mutable
			{
				return distribution_(random_engine_);
			};
			return random_function;
		};

		static const TCHAR alphabet[] =
			L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			L"abcdefghijklmnopqrstuvwxyz";
		L"0123456789";

		std::vector<int> indexes{};
		std::generate_n(std::back_inserter(indexes), size, random_numbers(0, wcslen(alphabet) - 1));


		std::wstring random_string(size, L'\x0');
		for (size_t i = 0; i < size; i++)
		{
			random_string[i] = alphabet[indexes[i]];
		}

		return random_string;
	}

	inline void in_replace_string(std::wstring& target_str, const std::wstring& pattern,
	                              const std::wstring& replace_str)
	{
		auto pos = target_str.find(pattern);

		while (pos != std::wstring::npos)
		{
			target_str.replace(pos, pattern.size(), replace_str);
			pos = target_str.find(pattern, pos + replace_str.size());
		}
	}


	template <class Container>
	std::ostream& write_container(const Container& c,
	                              std::ostream& out,
	                              const char delimiter = '\n')
	{
		auto write_sep = false;
		for (const auto& e : c)
		{
			if (write_sep)
				out << delimiter;
			else
				write_sep = true;
			out << e;
		}
		return out;
	}

	inline bool get_lines_from_file(const std::string& file_name, std::vector<std::string>& vec)
	{
		std::ifstream in(file_name.c_str());
		if (!in)
		{
			return false;
		}

		std::string str{};
		while (std::getline(in, str))
		{
			if (!str.empty())
			{
				vec.emplace_back(str);
			}
		}

		return true;
	}


	template <typename StringType>
	bool write_string_to_file(const std::wstring& file_path, StringType& content, const size_t size)
	{
		char data_buffer[] = "This is some test data to write to the file.";
		auto bytes_to_write = static_cast<DWORD>(strlen(data_buffer));
		DWORD bytes_written = 0;

		const auto file_handle = CreateFile(file_path.c_str(),
		                                    GENERIC_WRITE,
		                                    0,
		                                    nullptr,
		                                    CREATE_ALWAYS,
		                                    FILE_ATTRIBUTE_NORMAL,
		                                    nullptr);

		if (file_handle == INVALID_HANDLE_VALUE)
		{
			printf("Unable to open file \"%ls\" for write.\n", file_path.c_str());
			return false;
		}

		const auto status = WriteFile(
			file_handle,
			content.c_str(),
			size * sizeof(content[0]),
			&bytes_written,
			nullptr);

		if (FALSE == status)
		{
			printf("Unable to write to file: %ls\n", file_path.c_str());
			CloseHandle(file_handle);
			return false;
		}

		CloseHandle(file_handle);
		return true;
	}

	inline bool is_administrator_required(const std::wstring_view application_name)
	{
		using check_elevation_func = DWORD(LPCWSTR, PDWORD, HANDLE, PDWORD, PDWORD);

		const auto check_elevation = reinterpret_cast<check_elevation_func*>(GetProcAddress(
			LoadLibrary(L"kernel32.dll"), "CheckElevation"));

		DWORD run_level;
		DWORD flags;
		if (check_elevation(application_name.data(), &flags, nullptr, &run_level, nullptr) != 0U)
		{
			// application path is invalid
			return false;
		}

		return run_level > 0;
	}

	inline std::string read_file_content(const std::string& file_path)
	{
		std::ifstream file_stream(file_path, std::ios::binary);
		std::string file_content((std::istreambuf_iterator<char>(file_stream)),
		                         std::istreambuf_iterator<char>());
		file_stream.close();

		return file_content;
	}
} // namespace launchercli
