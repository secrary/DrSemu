#pragma once

#include "includes.h"

///////////////////////////////////////////////////////////////////////////////////////////////
// Virtualization instance control API wrappers.
///////////////////////////////////////////////////////////////////////////////////////////////

using namespace virtual_fs;

HRESULT virtualization_instance::Start(LPCWSTR rootPath,
	PRJ_STARTVIRTUALIZING_OPTIONS* options)
{
	_rootPath = rootPath;

	if (options == nullptr)
	{
		_options = PRJ_STARTVIRTUALIZING_OPTIONS();
	}
	else
	{
		_options = *options;
	}

	// Ensure we have a virtualization root directory that is stamped with an instance ID using the
	// PrjMarkDirectoryAsPlaceholder API.
	auto hr = EnsureVirtualizationRoot();

	if (FAILED(hr))
	{
		return hr;
	}

	// Register the required C callbacks.
	_callbacks.StartDirectoryEnumerationCallback = StartDirEnumCallback_C;
	_callbacks.EndDirectoryEnumerationCallback = EndDirEnumCallback_C;
	_callbacks.GetDirectoryEnumerationCallback = GetDirEnumCallback_C;
	_callbacks.GetPlaceholderInfoCallback = GetPlaceholderInfoCallback_C;
	_callbacks.GetFileDataCallback = GetFileDataCallback_C;

	// Register the optional C callbacks.

	// Register Notify if the provider says it implemented it, unless the provider didn't create any
	// notification mappings.
	if (((GetOptionalMethods() & OptionalMethods::Notify) != None) &&
		(_options.NotificationMappingsCount != 0))
	{
		_callbacks.NotificationCallback = NotificationCallback_C;
	}

	// Register QueryFileName if the provider says it implemented it.
	if ((GetOptionalMethods() & OptionalMethods::QueryFileName) != None)
	{
		_callbacks.QueryFileNameCallback = QueryFileName_C;
	}

	// Register CancelCommand if the provider says it implemented it.
	if ((GetOptionalMethods() & OptionalMethods::CancelCommand) != None)
	{
		_callbacks.CancelCommandCallback = CancelCommand_C;
	}

	// Start the virtualization instance.  Note that we pass our 'this' pointer in the instanceContext
	// parameter.  ProjFS will send this context back to us when calling our callbacks, which will
	// allow them to fish out this instance of the VirtualizationInstance class and call our methods.
	hr = PrjStartVirtualizing(_rootPath.c_str(),
		&_callbacks,
		this,
		&_options,
		&_instanceHandle);

	return hr;
}

void virtualization_instance::Stop()
{
	PrjStopVirtualizing(_instanceHandle);
}

HRESULT virtualization_instance::WritePlaceholderInfo(LPCWSTR relativePath,
	const PRJ_PLACEHOLDER_INFO* placeholderInfo,
	DWORD length)
{
	return PrjWritePlaceholderInfo(_instanceHandle,
		relativePath,
		placeholderInfo,
		length);
}

HRESULT virtualization_instance::WriteFileData(LPCGUID streamId,
	PVOID buffer,
	ULONGLONG byteOffset,
	DWORD length)
{
	return PrjWriteFileData(_instanceHandle,
		streamId,
		buffer,
		byteOffset,
		length);
}

/////////////////////////////////////////////////////////////////
// Default implementations for non-pure virtual callback methods.
/////////////////////////////////////////////////////////////////

HRESULT virtualization_instance::Notify(
	_In_ const PRJ_CALLBACK_DATA* CallbackData,
	_In_ BOOLEAN IsDirectory,
	_In_ PRJ_NOTIFICATION NotificationType,
	_In_opt_ PCWSTR DestinationFileName,
	_Inout_ PRJ_NOTIFICATION_PARAMETERS* NotificationParameters
)
{
	// If the derived provider implements this callback they must call SetOptionalMethods(OptionalMethods::Notify)
	// to cause the callback to be registered when starting the virtualization instance.

	return STATUS_NOT_IMPLEMENTED; //throw NotImplemented();
}

HRESULT virtualization_instance::QueryFileName(
	_In_ const PRJ_CALLBACK_DATA* CallbackData
)
{
	// If the derived provider implements this callback they must call SetOptionalMethods(OptionalMethods::QueryFileName)
	// to cause the callback to be registered when starting the virtualization instance.

	return STATUS_NOT_IMPLEMENTED; //throw NotImplemented();
}

void virtualization_instance::CancelCommand(
	_In_ const PRJ_CALLBACK_DATA* CallbackData
)
{
	// If the derived provider implements this callback they must call SetOptionalMethods(OptionalMethods::CancelCommand)
	// to cause the callback to be registered when starting the virtualization instance.
}

///////////////////////////////////////////////////////////////////////////////////////////////
// Getter/setter.
///////////////////////////////////////////////////////////////////////////////////////////////

// Gets the set of optional methods the derived class has indicated that it has implemented.
OptionalMethods virtualization_instance::GetOptionalMethods()
{
	return _implementedOptionalMethods;
}

// Sets the set of optional methods the derived class wants to indicate that it has implemented.
void virtualization_instance::SetOptionalMethods(OptionalMethods optionalMethodsToSet)
{
	_implementedOptionalMethods |= optionalMethodsToSet;
}


// Ensures that the directory _rootPath, which we want to use as the virtualization root, exists.
//
// If the _rootPath directory does not yet exist, this routine:
//  1. Creates the _rootPath directory.
//  2. Generates a virtualization instance ID.
//  3. Stores the ID in a file in the directory to mark it as the virtualization root.
//  4. Marks the directory as the virtualization root, using the PrjMarkDirectoryAsPlaceholder API
//     and the generated ID.
//
// If the _rootPath directory already exists, this routine checks for the file that should contain
// the stored ID.  If it exists, we assume this is our virtualization root.
HRESULT virtualization_instance::EnsureVirtualizationRoot()
{
	DWORD win32error;
	GUID instanceId;

	// Try creating our virtualization root.
	if (::CreateDirectory(_rootPath.c_str(), nullptr) == 0)
	{
		win32error = GetLastError();

		if (win32error == ERROR_ALREADY_EXISTS)
		{
			// The virtualization root already exists. Check for the stored virtualization instance
			// ID.
			const auto id_file_handle = CreateFile2((_rootPath + instance_id_file).c_str(),
				GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				OPEN_EXISTING,
				nullptr);

			if (id_file_handle == INVALID_HANDLE_VALUE)
			{
				win32error = GetLastError();
				return HRESULT_FROM_WIN32(win32error);
			}

			DWORD bytesRead;
			if (ReadFile(id_file_handle, &instanceId, sizeof(GUID), &bytesRead, nullptr) == 0)
			{
				win32error = GetLastError();
				CloseHandle(id_file_handle);
				return HRESULT_FROM_WIN32(win32error);
			}

			// If we didn't read sizeof(GUID) bytes then this might not be our directory.
			if (bytesRead != sizeof(GUID))
			{
				CloseHandle(id_file_handle);
				return HRESULT_FROM_WIN32(ERROR_BAD_CONFIGURATION);
			}

			CloseHandle(id_file_handle);
		}
		else
		{
			return HRESULT_FROM_WIN32(win32error);
		}
	}
	else
	{
		// We created a new directory.  Create a virtualization instance ID.
		auto hr = CoCreateGuid(&instanceId);
		if (hr != S_OK)
		{
			return hr;
		}

		// Store the ID in the directory as a way for us to detect that this is our directory in
		// the future.
		const auto id_file_handle = CreateFile2((_rootPath + instance_id_file).c_str(),
			GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			CREATE_NEW,
			nullptr);

		if (id_file_handle == INVALID_HANDLE_VALUE)
		{
			win32error = GetLastError();
			return HRESULT_FROM_WIN32(win32error);
		}

		DWORD bytesWritten;
		if (WriteFile(id_file_handle, &instanceId, sizeof(GUID), &bytesWritten, nullptr) == 0)
		{
			win32error = GetLastError();
			CloseHandle(id_file_handle);
			return HRESULT_FROM_WIN32(win32error);
		}

		CloseHandle(id_file_handle);

		// Mark the directory as the virtualization root.
		hr = PrjMarkDirectoryAsPlaceholder(_rootPath.c_str(),
			nullptr,
			nullptr,
			&instanceId);

		if (FAILED(hr))
		{
			// Let's do a best-effort attempt to clean up the directory.
			DeleteFile((_rootPath + instance_id_file).c_str());

			return hr;
		}
	}

	return S_OK;
}

///////////////////////////////////////////////////////////////////////////////////////////////
// The remaining methods are the callbacks we'll register with ProjFS.  Each one simply gets our
// 'this' pointer out of CallbackData->InstanceContext and invokes the corresponding method.
///////////////////////////////////////////////////////////////////////////////////////////////

HRESULT virtualization_instance::StartDirEnumCallback_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData,
	_In_ const GUID* EnumerationId
)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->StartDirEnum(CallbackData, EnumerationId);
}

HRESULT virtualization_instance::EndDirEnumCallback_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData,
	_In_ const GUID* EnumerationId
)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->EndDirEnum(CallbackData, EnumerationId);
}

HRESULT virtualization_instance::GetDirEnumCallback_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData,
	_In_ const GUID* EnumerationId,
	_In_opt_ PCWSTR SearchExpression,
	_In_ PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle
)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->GetDirEnum(CallbackData,
		EnumerationId,
		SearchExpression,
		DirEntryBufferHandle);
}

HRESULT virtualization_instance::GetPlaceholderInfoCallback_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData
)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->GetPlaceholderInfo(CallbackData);
}

HRESULT virtualization_instance::GetFileDataCallback_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData,
	_In_ UINT64 ByteOffset,
	_In_ UINT32 Length
)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->GetFileData(CallbackData,
		ByteOffset,
		Length);
}

HRESULT virtualization_instance::NotificationCallback_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData,
	_In_ BOOLEAN IsDirectory,
	_In_ PRJ_NOTIFICATION NotificationType,
	_In_opt_ PCWSTR DestinationFileName,
	_Inout_ PRJ_NOTIFICATION_PARAMETERS* NotificationParameters
)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->Notify(CallbackData,
		IsDirectory,
		NotificationType,
		DestinationFileName,
		NotificationParameters);
}

HRESULT virtualization_instance::QueryFileName_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	return instance->QueryFileName(CallbackData);
}

void virtualization_instance::CancelCommand_C(
	_In_ const PRJ_CALLBACK_DATA* CallbackData)
{
	auto instance = reinterpret_cast<virtualization_instance*>(CallbackData->InstanceContext);
	instance->CancelCommand(CallbackData);
}
