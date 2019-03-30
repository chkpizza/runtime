#include "dr_debugger.h"
#include <TlHelp32.h>

uint32_t get_pid()
{
	HANDLE snapshot_handle;
	PROCESSENTRY32 process_entry;


	process_entry.dwSize = sizeof(PROCESSENTRY32);
	snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (snapshot_handle == NULL)
	{
		printf("get_pid():: CreateToolhelp32Snapshot fail : %08X\n", GetLastError());
		return 0;
	}

	Process32First(snapshot_handle, &process_entry);
	do {
		if (!wcscmp(process_entry.szExeFile, L"testconsole.exe"))
		{
			printf("%ls : %d\n", process_entry.szExeFile, process_entry.th32ProcessID);
			CloseHandle(snapshot_handle);
			return process_entry.th32ProcessID;
		}
	} while (Process32Next(snapshot_handle, &process_entry));

	CloseHandle(snapshot_handle);
	return 0;
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

			dr6_backup = thread_context.Dr6;
			dr7_backup = thread_context.Dr7;
			thread_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			thread_context.Dr0 = (DWORD)0x00A510E0;

			thread_context.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
			
			if (!SetThreadContext(thread_handle, &thread_context))
			{
				printf("set_thread_context():: SetThreadContext fail : %08X\n", GetLastError());
			}
			break;
		}
	} while (Thread32Next(snapshot_handle, &thread_entry));

	CloseHandle(snapshot_handle);
	CloseHandle(thread_handle);
}
