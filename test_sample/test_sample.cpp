#include <Windows.h>
#include  <cstdio>
#include <memory>


int main()
{
	const auto file_handle = CreateFile(L"test_file.temp", GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, 0, 0);
	if (file_handle != INVALID_HANDLE_VALUE)
	{
		const std::shared_ptr<wchar_t> handle_path{ new wchar_t[0x1000] };
		memset(handle_path.get(), 0, 0x1000 * sizeof(wchar_t));

		GetFinalPathNameByHandle(file_handle, handle_path.get(), 0x1000, VOLUME_NAME_DOS);

		printf("file_path: %ls\n", handle_path.get());
		MessageBox(0, 0, 0, 0);
	}

	
}
