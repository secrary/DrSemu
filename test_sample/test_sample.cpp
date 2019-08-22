#include <Windows.h>
#include  <cstdio>
#include <memory>


int main()
{
	const auto file_handle = CreateFile(L"test_file.temp", GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
	if (file_handle != INVALID_HANDLE_VALUE)
	{
		const std::shared_ptr<wchar_t> handle_path{ new wchar_t[0x1000] };
		memset(handle_path.get(), 0, 0x1000 * sizeof(wchar_t));

		const auto size = GetFinalPathNameByHandle(file_handle, handle_path.get(), 0x1000 - sizeof(TCHAR), VOLUME_NAME_DOS);

		printf("file_path: %ls\nsize_in_tchars: %lu\nlast_error: %lu\n", handle_path.get(), size, GetLastError());
		MessageBox(nullptr, nullptr, nullptr, 0);
	}

	
}
