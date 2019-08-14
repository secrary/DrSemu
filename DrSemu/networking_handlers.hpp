#pragma once

#include "includes.h"

namespace dr_semu::networking::config
{
	inline bool disable_internet = false;
}

namespace dr_semu::networking::handlers
{
	inline void pro_wsa_startup(void* wrapcxt, void** user_data)
	{
		//int PASCAL FAR WSAStartup(
		//	_In_ WORD wVersionRequired,
		//	_Out_ LPWSADATA lpWSAData);

		constexpr auto args_size = sizeof(WORD) + sizeof(LPWSADATA);

		if (config::disable_internet)
		{
			drwrap_skip_call(wrapcxt, PVOID(WSASYSNOTREADY), args_size);
		}
	}

	inline void pro_url_download_to_file(void* wrapcxt, void** user_data)
	{
		// STDAPI URLDownloadToFileW(_In_opt_ LPUNKNOWN, _In_ LPCWSTR,_In_opt_ LPCWSTR,DWORD, _In_opt_ LPBINDSTATUSCALLBACK);      

		constexpr auto args_size = sizeof(LPUNKNOWN) + sizeof(LPCWSTR) + sizeof(LPCWSTR) + sizeof(DWORD) + sizeof(
			LPBINDSTATUSCALLBACK);

		const auto url = static_cast<LPCWSTR>(drwrap_get_arg(wrapcxt, 1));
		const auto file_name_opt = static_cast<LPCWSTR>(drwrap_get_arg(wrapcxt, 2));

		if (url == nullptr)
		{
			// Cannot be set to NULL. If the URL is invalid, INET_E_DOWNLOAD_FAILURE is returned.
			drwrap_skip_call(wrapcxt, PVOID(INET_E_DOWNLOAD_FAILURE), args_size);
			return;
		}

		const std::wstring target_url{ url };
		const auto target_file_name = file_name_opt != nullptr ? std::wstring{ file_name_opt } : L"";

		// trace call
		const std::string target_url_ascii(target_url.begin(), target_url.end());
		const std::string target_file_name_ascii(target_file_name.begin(), target_file_name.end());
		json url_download;
		url_download["URLDownloadToFile"]["before"] = {
			{"url", target_url_ascii.c_str()},
			{"file_path", target_file_name_ascii.c_str()},
		};
		dr_semu::shared_variables::json_concurrent_vector.push_back(url_download);
	}

	inline void pro_url_download_to_cache_file(void* wrapcxt, void** user_data)
	{
		// STDAPI URLDownloadToCacheFileW(_In_opt_ LPUNKNOWN, _In_ LPCWSTR, _Out_writes_(cchFileName) LPWSTR, DWORD cchFileName, DWORD, _In_opt_ LPBINDSTATUSCALLBACK);

		constexpr auto args_size = sizeof(LPUNKNOWN) + sizeof(LPCWSTR) + sizeof(LPWSTR) + sizeof(DWORD) + sizeof(DWORD)
			+ sizeof(LPBINDSTATUSCALLBACK);

		const auto url = static_cast<LPCWSTR>(drwrap_get_arg(wrapcxt, 1));
		if (url == nullptr)
		{
			// Cannot be set to NULL. If the URL is invalid, INET_E_DOWNLOAD_FAILURE is returned.
			drwrap_skip_call(wrapcxt, PVOID(INET_E_DOWNLOAD_FAILURE), args_size);
			return;
		}

		const std::wstring target_url{ url };
		const std::string target_url_ascii(target_url.begin(), target_url.end());

		// trace call
		json url_download_to_cache;
		url_download_to_cache["URLDownloadToCacheFile"]["before"] = {
			{"url", target_url_ascii.c_str()},
		};
		dr_semu::shared_variables::json_concurrent_vector.push_back(url_download_to_cache);
	}
} // namespace dr_semu::networking::handlers
