#include "includes.h"

using namespace virtual_fs;

std::wstring get_real_path(const std::wstring& relative_file_path)
{
	wchar_t* p_value = nullptr;
	size_t len;
	_wdupenv_s(&p_value, &len, L"SystemDrive");
	if (p_value == nullptr)
	{
		return L"";
	}
	std::wstring full_file_path{ p_value };
	free(p_value);

	full_file_path += L'\\';
	full_file_path += relative_file_path;

	return full_file_path;
}

_Success_(return)

bool get_file_basic_info(__in const std::wstring& file_path, __out PRJ_FILE_BASIC_INFO& basic_info)
{
	WIN32_FILE_ATTRIBUTE_DATA file_attributes{};
	const auto error_result = GetFileAttributesExW(file_path.data(), GetFileExInfoStandard, &file_attributes);
	if (error_result == 0)
	{
		return false;
	}

	basic_info.FileAttributes = file_attributes.dwFileAttributes;
	basic_info.IsDirectory = (file_attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U ? TRUE : FALSE;

	basic_info.CreationTime.LowPart = file_attributes.ftCreationTime.dwLowDateTime;
	basic_info.CreationTime.HighPart = file_attributes.ftCreationTime.dwHighDateTime;

	basic_info.LastAccessTime.LowPart = file_attributes.ftLastAccessTime.dwLowDateTime;
	basic_info.LastAccessTime.HighPart = file_attributes.ftLastAccessTime.dwHighDateTime;

	basic_info.LastWriteTime.LowPart = basic_info.ChangeTime.LowPart =
		file_attributes.ftLastWriteTime.dwLowDateTime;
	basic_info.LastWriteTime.HighPart = basic_info.ChangeTime.HighPart =
		file_attributes.ftLastWriteTime.dwHighDateTime;

	LARGE_INTEGER li;
	li.LowPart = file_attributes.nFileSizeLow;
	li.HighPart = file_attributes.nFileSizeHigh;
	basic_info.FileSize = basic_info.IsDirectory != 0U ? 0 : li.QuadPart;

	return true;
}


inline std::shared_ptr<PRJ_PLACEHOLDER_INFO> create_placeholder_info(
	__in const std::wstring& file_path, __out DWORD& size)
{
	size = FIELD_OFFSET(PRJ_PLACEHOLDER_INFO, VariableData[fs_descriptor.len]);
	std::shared_ptr<PRJ_PLACEHOLDER_INFO> placeholder_info(static_cast<PRJ_PLACEHOLDER_INFO*>(
		calloc(1, size)),
		free);

	memcpy_s(placeholder_info.get()->VariableData, fs_descriptor.len, fs_descriptor.ptr_sd.get(), fs_descriptor.len);


	placeholder_info->SecurityInformation.SecurityBufferSize = fs_descriptor.len;
	placeholder_info->SecurityInformation.OffsetToSecurityDescriptor = FIELD_OFFSET(PRJ_PLACEHOLDER_INFO, VariableData);

	if (!get_file_basic_info(file_path, placeholder_info->FileBasicInfo))
	{
		return nullptr;
	}

	//placeholder_info->SecurityInformation.SecurityBufferSize = 0;
	//placeholder_info->SecurityInformation.OffsetToSecurityDescriptor = 0;

	placeholder_info->StreamsInformation.StreamsInfoBufferSize = 0;
	placeholder_info->StreamsInformation.OffsetToFirstStreamInfo = 0;

	placeholder_info->EaInformation.EaBufferSize = 0;
	placeholder_info->EaInformation.OffsetToFirstEa = 0;


	return placeholder_info;
}

bool read_file_content(const std::wstring& path, PBYTE data, UINT32& len)
{
	const auto real_path = get_real_path(path);
	const auto file_handle = CreateFile(real_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0,
		nullptr);
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// If the function succeeds, the return value is nonzero (TRUE).
	const auto return_status = ReadFile(file_handle, data, len, nullptr, nullptr) != 0;
	CloseHandle(file_handle);

	// If the function succeeds, the return value is nonzero (TRUE).
	return !!return_status;
}


fs_provider::fs_provider()
{
	// Record that this class implements the optional Notify callback.
	this->SetOptionalMethods(OptionalMethods::Notify | OptionalMethods::QueryFileName);
}

/*++

Description:

	ProjFS invokes this callback to tell the provider that a directory enumeration is starting.

	A user-mode tool usually uses FindFirstFile/FindNextFile APIs to enumerate a directory.  Those
	APIs send QueryDirectory requests to the file system.  If the enumeration is for a placeholder
	folder, ProjFS intercepts and blocks those requests.  Then ProjFS invokes the registered directory
	enumeration callbacks (StartDirEnum, GetDirEnum, EndDirEnum) to get a list of names in provider's
	namespace, merges those names with the names physically on disk under that folder, then unblocks
	the enumeration requests and returns the merged list to the caller.

--*/
HRESULT fs_provider::StartDirEnum(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId)
{
	// For each dir enum session, ProjFS sends:
	//      one StartEnumCallback
	//      one or more GetEnumCallbacks
	//      one EndEnumCallback
	// These callbacks will use the same value for EnumerationId for the same session.
	// Here we map the EnumerationId to a new DirInfo object.
	active_enum_sessions_[*EnumerationId] = std::make_unique<dir_info>(CallbackData->FilePathName);


	return S_OK;
}


/*++

Description:

	ProjFS invokes this callback to tell the provider that a directory enumeration is over.  This
	gives the provider the opportunity to release any resources it set up for the enumeration.

--*/
HRESULT fs_provider::EndDirEnum(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId)
{
	// Get rid of the DirInfo object we created in StartDirEnum.
	active_enum_sessions_.erase(*EnumerationId);

	return S_OK;
}

/*++

Description:

	ProjFS invokes this callback to request a list of files and directories under the given directory.

	To handle this callback, the provider calls DirInfo->FillFileEntry/FillDirEntry for each matching file
	or directory.

	If the SearchExpression argument specifies something that doesn't exist in provider's namespace,
	or if the directory being enumerated is empty, the provider just returns S_OK without storing
	anything in DirEntryBufferHandle.  ProjFS will return the correct error code to the caller.

	Below is a list of example commands that will invoke GetDirectoryEntries callbacks.
	These assume you've cd'd into the virtualization root folder.

	Command                  CallbackData->FilePathName    SearchExpression
	------------------------------------------------------------------------
	dir                      ""(root folder)               *
	dir foo*                 ""(root folder)               foo*
	dir H + TAB              ""(root folder)               H*
	dir abc_dir				 ""(root folder)               abc_dir
	dir aabbcc?				 ""(root folder)               aabbcc>

	In the last example, the ">" character is the special wildcard value DOS_QM.  ProjFS handles this
	and other special file system wildcard values in its PrjFileNameMatch and PrjDoesNameContainWildCards
	APIs.

--*/
HRESULT fs_provider::GetDirEnum(const PRJ_CALLBACK_DATA* CallbackData, const GUID* EnumerationId,
	PCWSTR SearchExpression, PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle)
{
	auto hr = S_OK;

	if (SearchExpression == nullptr)
	{
		return E_INVALIDARG;
	}

	// Get the correct enumeration session from our map.
	auto it = active_enum_sessions_.find(*EnumerationId);
	if (it == active_enum_sessions_.end())
	{
		// We were asked for an enumeration we don't know about.
		hr = E_INVALIDARG;

		return hr;
	}

	// Get out our DirInfo helper object, which manages the context for this enumeration.
	auto& dir_info = it->second;

	// If the enumeration is restarting, reset our bookkeeping information.
	if ((CallbackData->Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN) != 0)
	{
		dir_info->reset();
	}

	if (!dir_info->EntriesFilled())
	{
		// The DirInfo associated with the current session hasn't been initialized yet.  This method
		// will enumerate the dirs and files in the real fs corresponding to CallbackData->FilePathName.
		// For each one that matches SearchExpression it will create an entry to return to ProjFS
		// and store it in the DirInfo object.
		const auto populate_result = populate_dir_info_for_path(CallbackData->FilePathName,
			dir_info.get(),
			SearchExpression);

		if (!populate_result)
		{
			return E_INVALIDARG;
		}

		// This will ensure the entries in the DirInfo are sorted the way the file system expects.
		dir_info->sort_entries_and_mark_filled();
	}

	// Return our directory entries to ProjFS.
	while (dir_info->current_is_valid())
	{
		// printf("Current_index: %d\n", dirInfo->get_current_index());

		// ProjFS allocates a fixed size buffer then invokes this callback.  The callback needs to
		// call PrjFillDirEntryBuffer to fill as many entries as possible until the buffer is full.

		auto current_basic_info = dir_info->current_basic_info();
		hr = PrjFillDirEntryBuffer(dir_info->current_file_name(),
			&current_basic_info,
			DirEntryBufferHandle);

		// If this routine returns HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) when adding an entry to the enumeration,
		// the provider returns S_OK from the callback and waits for the next PRJ_GET_DIRECTORY_ENUMERATION_CB callback.
		if (S_OK != hr)
		{
			// auto last_error = GetLastError();
			// printf("[ProjFS] PrjFillDirEntryBuffer failed. hr: 0x%x err: %d\nPath: %ls\n", hr, last_error, dirInfo->current_file_name());
			if (HRESULT_CODE(hr) == ERROR_INSUFFICIENT_BUFFER)
			{
				hr = S_OK;
			}
			break;
		}

		// Only move the current entry cursor after the entry was successfully filled, so that we
		// can start from the correct index in the next GetDirEnum callback for this enumeration
		// session.
		dir_info->move_next();
	}

	return hr;
}


HRESULT fs_provider::GetPlaceholderInfo(const PRJ_CALLBACK_DATA* CallbackData)
{
	const auto file_path = get_real_path(CallbackData->FilePathName);
	//printf("getholderinfo: %ls\n", file_path.c_str());

	DWORD size{};
	const auto placeholder_ptr = create_placeholder_info(file_path, size);
	if (!placeholder_ptr)
	{
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}

	const auto hr = this->WritePlaceholderInfo(CallbackData->FilePathName,
		placeholder_ptr.get(), size);

	if (S_OK != hr)
	{
		printf("[ProjFS] PrjWritePlaceholderInfo failed. hr: 0x%lx\nPath: %ls\n", hr, file_path.c_str());
	}

	return hr;
}


/*++

Description:

	ProjFS invokes this callback to request the contents of a file.

	To handle this callback, the provider issues one or more calls to WriteFileData() to give
	ProjFS the file content. ProjFS will convert the on-disk placeholder into a hydrated placeholder,
	populated with the file contents.  Afterward, subsequent file reads will no longer invoke the
	GetFileStream callback.

	If multiple threads read the same placeholder file simultaneously, ProjFS ensures that the provider
	receives only one GetFileStream callback.

	If the provider is unable to process the request, it return an appropriate error code.  The caller
	who issued the read will receive an error, and the next file read for the same file will invoke
	GetFileStream again.

	Below is a list of example commands that will invoke GetFileStream callbacks.
	Assume there's a file named 'testfile' in provider's namespace:

	type testfile
	echo 123>>testfile
	echo 123>testfile

--*/
HRESULT fs_provider::GetFileData(const PRJ_CALLBACK_DATA* CallbackData, UINT64 ByteOffset, UINT32 Length)
{
	auto hr = S_OK;

	if (Length == 0)
	{
		return hr;
	}

	// We're going to need alignment information that is stored in the instance to service this
	// callback.
	PRJ_VIRTUALIZATION_INSTANCE_INFO instance_info;
	hr = PrjGetVirtualizationInstanceInfo(_instanceHandle,
		&instance_info);

	if (FAILED(hr))
	{
		return hr;
	}

	// Allocate a buffer that adheres to the machine's memory alignment.  We have to do this in case
	// the caller who caused this callback to be invoked is performing non-cached I/O.  For more
	// details, see the topic "Providing File Data" in the ProjFS documentation.
	const auto write_buffer = PrjAllocateAlignedBuffer(_instanceHandle,
		Length);

	if (write_buffer == nullptr)
	{
		return E_OUTOFMEMORY;
	}

	// Read the data out of the registry.
	if (!read_file_content(CallbackData->FilePathName, reinterpret_cast<PBYTE>(write_buffer), Length))
	{
		hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

		PrjFreeAlignedBuffer(write_buffer);

		return hr;
	}

	// Call ProjFS to write the data we read from the registry into the on-disk placeholder.
	hr = this->WriteFileData(&CallbackData->DataStreamId,
		reinterpret_cast<PVOID>(write_buffer),
		ByteOffset,
		Length);

	if (FAILED(hr))
	{
		// If this callback returns an error, ProjFS will return this error code to the thread that
		// issued the file read, and the target file will remain an empty placeholder.
		wprintf(L"%hs: failed to write file for [%s]: 0x%08x\n",
			__FUNCTION__, CallbackData->FilePathName, hr);
	}

	// Free the memory-aligned buffer we allocated.
	PrjFreeAlignedBuffer(write_buffer);

	return hr;
}


HRESULT fs_provider::Notify(const PRJ_CALLBACK_DATA* CallbackData, BOOLEAN IsDirectory,
	PRJ_NOTIFICATION NotificationType, PCWSTR DestinationFileName,
	PRJ_NOTIFICATION_PARAMETERS* NotificationParameters)
{
	// allow
	return HRESULT_FROM_WIN32(STATUS_SUCCESS);
}

HRESULT fs_provider::QueryFileName(const PRJ_CALLBACK_DATA* CallbackData)
{
	return S_OK;
}


bool fs_provider::populate_dir_info_for_path(const std::wstring& relative_path, dir_info* dir_info,
	const std::wstring& search_expression)
{
	const auto file_path = get_real_path(relative_path);


	std::error_code ec{};
	for (const auto& file : std::filesystem::directory_iterator(file_path, ec))
	{
		if (ec.value() != STATUS_SUCCESS)
		{
			continue;
		}

		const auto filename = file.path().filename().wstring();
		if (search_expression.empty() || PrjFileNameMatch(filename.c_str(), search_expression.c_str()) != 0U)
		{
			dir_entry entry{};
			entry.file_name = filename;
			PRJ_FILE_BASIC_INFO basic_info{};
			auto is_valid = get_file_basic_info(file.path().wstring(), basic_info);
			if (is_valid)
			{
				entry.basic_info = basic_info;
				dir_info->fill_entry(entry);
			}
		}
	}

	return true;
}
