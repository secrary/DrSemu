#define STRICT_TYPED_ITEMIDS
// http://www.suodenjoki.dk/us/archive/2010/min-max.htm
#define NOMINMAX

#include <windows.h>      // Standard include
#include <Shellapi.h>     // Included for shell constants such as FO_* values
#include <shlobj.h>       // Required for necessary shell dependencies
#include <strsafe.h>      // Including StringCch* helpers
#include <string>

inline HRESULT create_and_initialize_file_operation(REFIID riid, void** ppv)
{
	*ppv = nullptr;
	// Create the IFileOperation object
	IFileOperation* pfo;
	auto hr = CoCreateInstance(__uuidof(FileOperation), nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pfo));
	if (SUCCEEDED(hr))
	{
		// Set the operation flags.  Turn off  all UI
		// from being shown to the user during the
		// operation.  This includes error, confirmation
		// and progress dialogs.
		hr = pfo->SetOperationFlags(FOF_NO_UI);
		if (SUCCEEDED(hr))
		{
			hr = pfo->QueryInterface(riid, ppv);
		}
		pfo->Release();
	}
	return hr;
}

inline HRESULT delete_files(IShellItem* psi_src)
{
	if (psi_src == nullptr)
	{
		return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
	}
	IFileOperation* pfo;
	auto hr = create_and_initialize_file_operation(IID_PPV_ARGS(&pfo));
	if (SUCCEEDED(hr))
	{
		hr = pfo->DeleteItem(psi_src, nullptr);
		if (SUCCEEDED(hr))
		{
			hr = pfo->PerformOperations();
		}
		pfo->Release();
	}
	return hr;
}

inline bool delete_directory(const std::wstring& dir_path)
{
	auto is_success = false;
	const auto hr = CoInitializeEx(
		nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (SUCCEEDED(hr))
	{
		IShellItem* item = nullptr;
		SHCreateItemFromParsingName(dir_path.c_str(), nullptr, IID_PPV_ARGS(&item));
		const auto hr_status = delete_files(item);
		if (hr_status == HRESULT_FROM_WIN32(ERROR_SUCCESS))
		{
			is_success = true;
		}

		CoUninitialize();
		return is_success;
	}

	return is_success;
}
