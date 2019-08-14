#pragma once

namespace virtual_fs
{
	struct fs_security_descriptor
	{
		DWORD len{};
		std::shared_ptr<byte> ptr_sd{};
	};

	// security descriptor for files and dirs
	inline fs_security_descriptor fs_descriptor{};

	class fs_provider final : public virtualization_instance
	{
	public:

		fs_provider();

	private:

		///////////////////////////////////////////////////////////////////////////////////////////////
		// Overrides of the virtual callback functions from the VirtualizationInstance base class that
		// this class will implement.
		///////////////////////////////////////////////////////////////////////////////////////////////

		HRESULT StartDirEnum(
			_In_ const PRJ_CALLBACK_DATA* CallbackData,
			_In_ const GUID* EnumerationId
		) override;

		HRESULT EndDirEnum(
			_In_ const PRJ_CALLBACK_DATA* CallbackData,
			_In_ const GUID* EnumerationId
		) override;

		HRESULT GetDirEnum(
			_In_ const PRJ_CALLBACK_DATA* CallbackData,
			_In_ const GUID* EnumerationId,
			_In_opt_ PCWSTR SearchExpression,
			_In_ PRJ_DIR_ENTRY_BUFFER_HANDLE DirEntryBufferHandle
		) override;


		/*++

		Description:

			ProjFS invokes this callback to request metadata information for a file or a directory.

			If the file or directory exists in the provider's namespace, the provider calls
			WritePlaceholderInfo() to give ProjFS the info for the requested name.

			The metadata information ProjFS supports includes:

				Mandatory:
					FileBasicInfo.IsDirectory - the requested name is a file or directory.

				Mandatory for files:
					FileBasicInfo.FileSize - file size in bytes.

				Optional:
					VersionInfo - A 256 bytes ID which can be used to distinguish different versions of file content
								  for one file name.
					FileBasicInfo.CreationTime/LastAccessTime/LastWriteTime/ChangeTime - timestamps of the file.
					FileBasicInfo.FileAttributes - File Attributes.

				Optional and less commonly used:
					EaInformation - Extended attribute (EA) information.
					SecurityInformation - Security descriptor information.
					StreamsInformation - Alternate data stream information.

			See also PRJ_PLACEHOLDER_INFORMATION structure in projectedfslib.h for more details.

			If the file or directory doesn't exist in the provider's namespace, this callback returns
			HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND).

			If the provider is unable to process the request (e.g. due to network error) or it wants to block
			the request, this callback returns an appropriate HRESULT error code.

			Assuming z:\fs doesn't exist, run '__.exe z:\fs' to create the root.
			Now start another command line window, 'cd z:\fs' then run below commands in sequence.

			1) cd abc_dir
			   The first time you cd into a folder that exists in provider's namespace, GetPlaceholderInfo is
			   called with CallbackData->FilePathName = "abc_dir".  This callback will cause an
			   on-disk placeholder file called "abc_dir" to be created under z:\fs.

			2) cd .. & cd abc_dir
			   The second and subsequent time you cd into a folder that exists in provider's namespace, this
			   callback will not be called because the on-disk placeholder for abc_dir already exists.

			3) mkdir newfolder
			   If _readonlyNamespace is true, GetPlaceholderInfo returns ERROR_ACCESS_DENIED, so the mkdir command
			   reports "Access is denied" and the placeholder is not created.  If _readonlyNamespace is false,
			   GetPlaceholderInfo returns ERROR_FILE_NOT_FOUND so the command succeeds and newfolder is created.

			4) cd bbb\ccc\ddd
			   The first time you cd into a deep path, GetPlaceholderInfo is called repeatedly with the
			   following CallbackData->FilePathName values:
			   1) "abc_dir\bbb"
			   2) "abc_dir\bbb\ccc"
			   3) "abc_dir\bbb\ccc\ddd"

		--*/
		HRESULT GetPlaceholderInfo(
			_In_ const PRJ_CALLBACK_DATA* CallbackData
		) override;

		HRESULT GetFileData(
			_In_ const PRJ_CALLBACK_DATA* CallbackData,
			_In_ UINT64 ByteOffset,
			_In_ UINT32 Length
		) override;

		/*++

		Description:

			ProjFS invokes this callback to deliver notifications of file system operations.

			The provider can specify which notifications it wishes to receive by filling out an array of
			PRJ_NOTIFICATION_MAPPING structures that it feeds to PrjStartVirtualizing in the PRJ_STARTVIRTUALIZING_OPTIONS
			structure.

			For the following notifications the provider can return a failure code.  This will prevent the
			associated file system operation from taking place.

			PRJ_NOTIFICATION_FILE_OPENED
			PRJ_NOTIFICATION_PRE_DELETE
			PRJ_NOTIFICATION_PRE_RENAME
			PRJ_NOTIFICATION_PRE_SET_HARDLINK
			PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL

			All other notifications are informational only.

			See also the PRJ_NOTIFICATION_TYPE enum for more details about the notification types.

		--*/
		HRESULT Notify(
			_In_ const PRJ_CALLBACK_DATA* CallbackData,
			_In_ BOOLEAN IsDirectory,
			_In_ PRJ_NOTIFICATION NotificationType,
			_In_opt_ PCWSTR DestinationFileName,
			_Inout_ PRJ_NOTIFICATION_PARAMETERS* NotificationParameters
		) override;

		HRESULT QueryFileName(
			_In_ const PRJ_CALLBACK_DATA* CallbackData
		) override;

		// Helper routine 
		static bool populate_dir_info_for_path(
			_In_ const std::wstring& relative_path,
			_In_ dir_info* dir_info,
			_In_ const std::wstring& search_expression
		);


		// An enumeration session starts when StartDirEnum is invoked and ends when EndDirEnum is invoked.
		// This tracks the active enumeration sessions.
		std::map<GUID, std::unique_ptr<dir_info>, GUIDComparer> active_enum_sessions_;
	};
} // namespace virtual_fs
