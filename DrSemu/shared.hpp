#pragma once

#include <Windows.h>
#include <cstdio>
#include <string>
#include <memory>
#include <Wincrypt.h>
#include <filesystem>

#define SECONDS *1000 // ms to s

namespace fs = std::filesystem;

namespace dr_semu::shared
{
	namespace constants
	{
		const std::wstring FAILED = L"FAILED";
		const std::wstring SUCCEED = L"SUCCEED";
		const std::wstring x86 = L"x86";
		const std::wstring x64 = L"x64";
	}

	inline std::wstring get_random_string(const size_t size)
	{
		std::srand(static_cast<unsigned int>(time(nullptr)));
		static const TCHAR alphabet[] =
			L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			L"abcdefghijklmnopqrstuvwxyz";
		std::wstring rand_string(size, '\x0');
		for (auto& i : rand_string)
		{
			i = alphabet[std::rand() / (RAND_MAX / (wcslen(alphabet) - 1) + 1)];
		}

		return rand_string;
	}

	struct pipe
	{
		HANDLE pipe_handle = nullptr;
		std::wstring pipe_name{};

		[[nodiscard]] bool is_valid() const
		{
			return (pipe_handle != nullptr) && pipe_handle != INVALID_HANDLE_VALUE;
		}

		explicit pipe(const std::wstring& pipe_name, const bool create = true) : pipe_name{ pipe_name }
		{
			const auto full_pipe_name = std::wstring{ LR"(\\.\pipe\)" } +pipe_name;
			if (create)
			{
				pipe_handle = CreateNamedPipe(
					full_pipe_name.c_str(),
					PIPE_ACCESS_DUPLEX,
					PIPE_TYPE_BYTE,
					1,
					0,
					0,
					0,
					nullptr
				);
				if (INVALID_HANDLE_VALUE == pipe_handle)
				{
					printf("Failed to create a duplex pipe\npipe_name: %ls\n", full_pipe_name.c_str());
				}
			}
			else
			{
				pipe_handle = CreateFile(
					full_pipe_name.c_str(),
					GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					nullptr,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					nullptr
				);
				if (INVALID_HANDLE_VALUE == pipe_handle)
				{
					printf("Failed to connect pipe. pipe_name: %ls\nlast err: 0x%lx\n", full_pipe_name.c_str(),
						GetLastError()); // log to a file
				}
			}
		}

		_Success_(return)

			[[nodiscard]] bool wait_for_client() const
		{
			// If the function succeeds, the return value is nonzero.
			return ConnectNamedPipe(pipe_handle, nullptr) != 0;
		}


		[[nodiscard]] bool write_pipe(const std::wstring& content) const
		{
			if (!is_valid())
			{
				return false;
			}

			DWORD number_of_bytes_written{};
			const auto result = WriteFile(
				pipe_handle,
				content.c_str(),
				(content.length() + 1) * sizeof(wchar_t),
				&number_of_bytes_written,
				nullptr
			);

			if (result == 0)
			{
				printf("WriteFile [pipe] failed with 0x%lx\npipe_name: %ls\npipe_handle: 0x%lx\n", GetLastError(),
					pipe_name.c_str(), reinterpret_cast<DWORD>(pipe_handle));
				return false;
			}

			return true;
		}

		_Success_(return)

			bool read_pipe(__out std::wstring& content) const
		{
			if (!is_valid())
			{
				return false;
			}

			const DWORD buffer_size = 0x1000;

			/// buffer_size is always 0; TODO: check ways to get a size of the buffer
			//do {
			//	if (!GetNamedPipeInfo(pipe_handle, nullptr, &buffer_size, 0, nullptr)) {
			//		printf("PeekNamedPipe [pipe] failed with 0x%lx\npipe_name: %ls\npipe_handle: 0x%x\n", GetLastError(), pipe_name.c_str(), pipe_handle);
			//		MessageBox(nullptr, L"failed", L"", 0);
			//		return false;
			//	}
			//	printf("x: %d\n", buffer_size);
			//} while (buffer_size == 0);

			const std::shared_ptr<byte> message_buffer{ new byte[buffer_size] };
			memset(message_buffer.get(), 0, buffer_size);

			DWORD read_bytes{};
			const auto result = ReadFile(pipe_handle,
				message_buffer.get(),
				buffer_size,
				&read_bytes,
				nullptr);

			if (result == 0)
			{
				printf("ReadFile [pipe] failed with 0x%lx\npipe_name: %ls\npipe_handle: 0x%lx\n", GetLastError(),
					pipe_name.c_str(), (DWORD)(pipe_handle));
				MessageBox(nullptr, L"failed", L"", 0);
				return false;
			}

			if (read_bytes == 0)
			{
				printf("ReadFile [pipe] failed (zero length) with 0x%lx\npipe_name: %ls\npipe_handle: 0x%lx\n",
					GetLastError(), pipe_name.c_str(), (DWORD)pipe_handle);
				MessageBox(nullptr, L"failed", L"", 0);
				return false;
			}

			content = std::wstring(reinterpret_cast<PWCHAR>(message_buffer.get()),
				wcslen(reinterpret_cast<PWCHAR>(message_buffer.get())));
			return true;
		}

		pipe() = delete;
		pipe(const pipe& other) = delete;
		pipe(pipe&& other) = delete;
		pipe& operator=(const pipe& other) = delete;
		pipe& operator=(pipe&& other) = delete;

		~pipe()
		{
			if (is_valid())
			{
				CloseHandle(pipe_handle);
			}
		}
	};

	struct slot
	{
		HANDLE slot_handle = nullptr;
		std::wstring mailslot_name{};

		[[nodiscard]] bool is_valid() const
		{
			return (slot_handle != nullptr) && slot_handle != INVALID_HANDLE_VALUE;
		}

		void close_slot()
		{
			if (is_valid())
			{
				CloseHandle(slot_handle);
				slot_handle = nullptr;
			}
		}

		// create a mailslot or open it
		explicit slot(const std::wstring& mailslot_name, const bool create = true) : mailslot_name{ mailslot_name }
		{
			const auto full_mailslot_name = std::wstring{ LR"(\\.\mailslot\)" } +mailslot_name;
			if (create)
			{
				slot_handle = CreateMailslot(full_mailslot_name.c_str(),
					0, // no maximum message size 
					MAILSLOT_WAIT_FOREVER, // no time-out for operations 
					nullptr); // default security

				if (slot_handle == INVALID_HANDLE_VALUE)
				{
					printf("CreateMailslot failed with 0x%lx\n", GetLastError());
				}
			}
			else
			{
				slot_handle = CreateFile(full_mailslot_name.c_str(),
					GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					nullptr,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					nullptr);

				if (slot_handle == INVALID_HANDLE_VALUE)
				{
					printf("CreateFile [slot] failed with 0x%lx\nname: %ls\n", GetLastError(), mailslot_name.c_str());
				}
			}
		}

		[[nodiscard]] bool write_slot(const std::wstring& content) const
		{
			if (!is_valid())
			{
				return false;
			}

			DWORD number_of_bytes_written{};
			const auto result = WriteFile(slot_handle,
				content.c_str(),
				static_cast<DWORD>(content.length() + 1) * sizeof(TCHAR),
				&number_of_bytes_written,
				nullptr);

			if (result == 0)
			{
				printf("WriteFile [slot] failed with 0x%lx\nhandle: 0x%lx\n", GetLastError(),
					reinterpret_cast<DWORD_PTR>(slot_handle));
				return false;
			}

			return true;
		}

		_Success_(return)

			bool read_slot(__out std::wstring& content) const
		{
			if (!is_valid())
			{
				return false;
			}

			DWORD next_message_size_bytes{};

			do
			{
				const auto result = GetMailslotInfo(slot_handle, // mailslot handle 
					nullptr, // no maximum message size 
					&next_message_size_bytes, // size of next message 
					nullptr, // number of messages 
					nullptr); // no read time-out 
				if (result == 0)
				{
					printf("GetMailslotInfo [slot] failed with 0x%lx\n", GetLastError());
					return false;
				}
				Sleep(1 SECONDS);
			} while (next_message_size_bytes == MAILSLOT_NO_MESSAGE);

			const std::shared_ptr<byte> message_buffer{ new byte[next_message_size_bytes] };
			memset(message_buffer.get(), 0, next_message_size_bytes);

			DWORD read_bytes{};
			const auto result = ReadFile(slot_handle,
				message_buffer.get(),
				next_message_size_bytes,
				&read_bytes,
				nullptr);

			if (result == 0)
			{
				printf("ReadFile [slot] failed with 0x%lx\n", GetLastError());
				return false;
			}

			content = std::wstring(reinterpret_cast<PWCHAR>(message_buffer.get()),
				wcslen(reinterpret_cast<PWCHAR>(message_buffer.get())));
			return true;
		}

		slot() = delete;
		slot(const slot& other) = delete;
		slot(slot&& other) = delete;
		slot& operator=(const slot& other) = delete;
		slot& operator=(slot&& other) = delete;

		~slot()
		{
			close_slot();
		}
	};
} // namespace dr_semu::shared
