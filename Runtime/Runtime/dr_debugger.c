#include "dr_debugger.h"

void inject_vehdbg_library()
{
	uint32_t target_pid = 0;
	target_pid = get_pid();
	
}

uint32_t get_pid()
{
	HANDLE snapshot_handle;
	PROCESSENTRY32 process_entry;
	UINT process_cnt = 1;

	process_entry.dwSize = sizeof(PROCESSENTRY32);
	snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (snapshot_handle == NULL)
	{
		printf("get_pid():: CreateToolhelp32Snapshot fail : %08X\n", GetLastError());
		return 0;
	}

	Process32First(snapshot_handle, &process_entry);
	do {
		printf("[%d]. %ws\n", process_entry.th32ProcessID , process_entry.szExeFile);
		process_cnt++;
	} while (Process32Next(snapshot_handle, &process_entry));

	system("pause");

	Process32First(snapshot_handle, &process_entry);
	do {
		if (!wcscmp(process_entry.szExeFile, L"ALKeeper.exe"))
		{
			//printf("%ls : %d\n", process_entry.szExeFile, process_entry.th32ProcessID);
			CloseHandle(snapshot_handle);
			return process_entry.th32ProcessID;
		}
	} while (Process32Next(snapshot_handle, &process_entry));

	CloseHandle(snapshot_handle);
	return 0;
}

void get_readable_memory_list(uint32_t image_base, uint32_t image_size, HANDLE target_process_handle)
{
	uint32_t start_addr = image_base;
	uint32_t end_addr = image_base + image_size;
	uint32_t loop_count = 0;
	MEMORY_BASIC_INFORMATION mbi;

	readable_memory_count = 0;

	while (start_addr < end_addr)
	{
		memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
		if (VirtualQueryEx(target_process_handle, (LPVOID)(ULONG_PTR)start_addr, &mbi, sizeof(mbi)) == sizeof(mbi))
		{
			if (mbi.State == MEM_COMMIT)
			{
				if ((mbi.Protect == PAGE_EXECUTE_READ) ||
					(mbi.Protect == PAGE_EXECUTE_READWRITE) || (mbi.Protect == PAGE_EXECUTE_WRITECOPY) ||
					(mbi.Protect == PAGE_READONLY) || (mbi.Protect == PAGE_READWRITE))
				{
					printf("readable_memory_list %08X - %08X\n", mbi.BaseAddress, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
					readable_memory_count++;
				}
			}
		}
		else {
			printf("222\n");
		}
		start_addr += mbi.RegionSize;
	}

	memory_list = (PREADABLE_MEMORY_LIST)malloc(sizeof(READABLE_MEMORY_LIST) * readable_memory_count);

	start_addr = image_base;
	while (start_addr < end_addr)
	{
		memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
		if (VirtualQueryEx(target_process_handle, (LPVOID)(ULONG_PTR)start_addr, &mbi, sizeof(mbi)) == sizeof(mbi))
		{
			if (mbi.State == MEM_COMMIT)
			{
				if ((mbi.Protect == PAGE_EXECUTE_READ) ||
					(mbi.Protect == PAGE_EXECUTE_READWRITE) || (mbi.Protect == PAGE_EXECUTE_WRITECOPY) ||
					(mbi.Protect == PAGE_READONLY) || (mbi.Protect == PAGE_READWRITE))
				{
					memory_list[loop_count].start_addr = (uint32_t)mbi.BaseAddress;
					memory_list[loop_count].addr_size = (uint32_t)mbi.RegionSize;
					memory_list[loop_count].protect = (uint32_t)mbi.Protect;
					printf("[%d] %08X --- %08X\n", loop_count, memory_list[loop_count].start_addr,
						memory_list[loop_count].addr_size);
					loop_count++;
				}
			}
		}
		start_addr += mbi.RegionSize;
	}
}

void set_thread_context()
{
	uint32_t debug_pid = 0;
	CONTEXT thread_context;
	HANDLE snapshot_handle = NULL;
	HANDLE thread_handle = NULL;
	THREADENTRY32 thread_entry;
	uint32_t index = 0;
	DWORD dr6_backup = 0;
	DWORD dr7_backup = 0;

	memset(&thread_context, 0, sizeof(CONTEXT));
	memset(&thread_entry, 0, sizeof(thread_entry));
	debug_pid = get_pid();
	
	if (debug_pid == 0)
	{
		printf("get_pid() fail\n");
		return;
	}

	snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot_handle == NULL)
	{
		printf("set_thread_context():: CreateToolhelp32Snapshot() fail : %08X\n", GetLastError());
		return;
	}
	thread_entry.dwSize = sizeof(thread_entry);
	
	
	if (!Thread32First(snapshot_handle, &thread_entry))
		printf("set_thread_context():: Thread32First fail : %08X\n", GetLastError());

	do {
		if (debug_pid == thread_entry.th32OwnerProcessID)
		{
			thread_handle = OpenThread(THREAD_ALL_ACCESS, 0, thread_entry.th32ThreadID);
			if (thread_handle == NULL)
			{
				printf("[%d] set_thread_context():: OpenThread fail : %08X\n", thread_entry.th32ThreadID, GetLastError());
				CloseHandle(snapshot_handle);
				break;
			}

			SuspendThread(thread_handle);

			dr6_backup = thread_context.Dr6;
			dr7_backup = thread_context.Dr7;
			thread_context.EFlags |= 0x100;
			thread_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			thread_context.Dr0 = (DWORD)0x56A9E800;
			thread_context.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);

			if (!SetThreadContext(thread_handle, &thread_context))
			{
				printf("set_thread_context():: SetThreadContext fail : %08X\n", GetLastError());
			}
			ResumeThread(thread_handle);
			//break;	-> 모든 스레드 컨텍스트에 대해 h/w bp를 걸기 위해 break 구문 삭제
		}
	} while (Thread32Next(snapshot_handle, &thread_entry));

	system("pause");
	CloseHandle(snapshot_handle);
	CloseHandle(thread_handle);
}
