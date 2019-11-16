/*
	VEH Debugger로 디버깅시 RtlEnterCriticalSection 함수 진입시 크래쉬가 발생함
	(CheatEngine VEH Debugger도 동일한 현상이 발생함)
*/

#pragma once

#include "veh_debugger.h"

void start();
int check_running_os();

int count = 0;
int call_cnt = 0;

LONG WINAPI veh_debug_handler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
);

char tmp_buffer[512];
int step_count = 0;

BOOL __stdcall DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	HANDLE start_func = NULL;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hInstDLL);
		start_func = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start, NULL, 0, NULL);
		CloseHandle(start_func);
	}
	return TRUE;
}

void start()
{
	int i = 0;
	int running_os_version = 0;
	uint32_t image_base, image_size;

	MessageBoxA(NULL, "inject success", " ", MB_OK);

	call_cnt = 0;
	if (set_veh_debugger_config() == FALSE)
	{
		return;
	}

	running_os_version = check_running_os();

	if (running_os_version == OS_VERSION_GET_FAIL)
	{
		MessageBoxA(NULL, "running os version get fail.. => exit", " ", MB_OK);
	}
	else
	{
		switch (running_os_version)
		{
		case OS_WINDOWS7_MAJOR:
			insert_veh_win7((DWORD)veh_debug_handler);
			MessageBoxA(NULL, "insert veh windows7", " ", MB_OK);
			break;


		case OS_WINDOWS10_MAJOR:
			insert_veh_win10((DWORD)veh_debug_handler);
			MessageBoxA(NULL, "insert veh windows10", " ", MB_OK);
			break;

		default:
			break;

		}
		get_target_process_info(&image_base, &image_size);
	}
}

BOOL set_veh_debugger_config()
{
	UINT loop_cnt = 0;
	char test_buffer[256];
	memset(test_buffer, 0, sizeof(test_buffer));

	memset(veh_except_function_list, 0, sizeof(veh_except_function_list));

	if (get_veh_except_function_address(veh_except_function_list) < EXCEPT_FUNCTION_COUNT)
	{
		MessageBoxA(NULL, "get_veh_except_function_address fail", " ", MB_OK);
		return FALSE;
	}

	sprintf(test_buffer, "test_buffer : %08X / %d", veh_except_function_list[0], 1);
	MessageBoxA(NULL, test_buffer, " ", MB_OK);

	return TRUE;
}

int check_running_os()
{
	int os_version = 0;
	LPWKSTA_INFO_100 pw_info = NULL;

	if (NetWkstaGetInfo(NULL, 100, (LPBYTE*)&pw_info) != NERR_Success)
	{
		os_version = OS_VERSION_GET_FAIL;
	}

	os_version = pw_info->wki100_ver_major;
	return os_version;
}

/*
	VEH Debugger Handler 함수

	모든 디버깅 관련 처리를 해당 함수에서 한다
*/
LONG WINAPI veh_debug_handler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	PBYTE target_memory_hex = NULL;
	UINT read_memory_size = 0;
	UINT loop_cnt = 0;
	BOOL bypass_flag = FALSE;	//step over flag
	BOOL exit_flag = FALSE;		//single step exit flag
	DWORD next_line = 0;

	int tmp_mb_result = 0;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		disasm((UINT)ExceptionInfo->ExceptionRecord->ExceptionAddress, &next_line);
		memset(tmp_buffer, 0, 512);
		step_count++;
		////////////////////////////////////////////////////////////////////////////////////////
		sprintf(tmp_buffer, "[EBP %08X] [ESP %08X] [EAX %08X] [ECX %08X] [EDX %08X] [ESI %08X] [EDI %08X] [DR0 %08X]\r\n",
			ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Eax,
			ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx, ExceptionInfo->ContextRecord->Esi,
			ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Dr0);
		write_log(tmp_buffer);
		memset(tmp_buffer, 0, 512);
		////////////////////////////////////////////////////////////////////////////////////////

		sprintf(tmp_buffer, "exception addr : %08X\neip : %08X\nexception code : %08X\n ESP : %08X EBP : %08X ECX : %08X EDX : %08X EDI : %08X ESI : %08X EAX: %08X\n",
			ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Eip,
			ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx,
			ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Esi, ExceptionInfo->ContextRecord->Eax);

		ExceptionInfo->ContextRecord->EFlags |= 0x100;
		ExceptionInfo->ContextRecord->Dr0 = 0;
		ExceptionInfo->ContextRecord->Dr1 = 0;
		ExceptionInfo->ContextRecord->Dr2 = 0;
		ExceptionInfo->ContextRecord->Dr3 = 0;
		ExceptionInfo->ContextRecord->Dr6 = 0;
		ExceptionInfo->ContextRecord->Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
		ExceptionInfo->ContextRecord->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
		
		tmp_mb_result = MessageBoxA(NULL, tmp_buffer, "[OK => break]", MB_YESNOCANCEL);

		if(tmp_mb_result == IDNO)
		{
			//step_run(0x75BC5C50, ExceptionInfo->ContextRecord);

			step_rewind(&context, ExceptionInfo->ContextRecord);
		}

		else if(tmp_mb_result == IDCANCEL)
		{
			if (next_line != 0)
			{
				step_over(ExceptionInfo->ContextRecord, next_line);
			}
		}

		/*
			step_rewind를 위해 현재 Context를 저장
		*/
		context.ContextFlags = ExceptionInfo->ContextRecord->ContextFlags;
		context.Dr0 = (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress;
		context.Dr1 = ExceptionInfo->ContextRecord->Dr1;
		context.Dr2 = ExceptionInfo->ContextRecord->Dr2;
		context.Dr3 = ExceptionInfo->ContextRecord->Dr3;
		context.Dr6 = ExceptionInfo->ContextRecord->Dr6;
		context.Dr7 = ExceptionInfo->ContextRecord->Dr7;
		context.FloatSave = ExceptionInfo->ContextRecord->FloatSave;


		context.SegGs = ExceptionInfo->ContextRecord->SegGs;
		context.SegFs = ExceptionInfo->ContextRecord->SegFs;
		context.SegEs = ExceptionInfo->ContextRecord->SegEs;
		context.SegDs = ExceptionInfo->ContextRecord->SegDs;

		context.Edi = ExceptionInfo->ContextRecord->Edi;
		context.Esi = ExceptionInfo->ContextRecord->Esi;
		context.Ebx = ExceptionInfo->ContextRecord->Ebx;
		context.Edx = ExceptionInfo->ContextRecord->Edx;
		context.Ecx = ExceptionInfo->ContextRecord->Ecx;
		context.Eax = ExceptionInfo->ContextRecord->Eax;

		context.Ebp = ExceptionInfo->ContextRecord->Ebp;
		context.Eip = ExceptionInfo->ContextRecord->Eip;
		context.SegCs = ExceptionInfo->ContextRecord->SegCs;
		context.EFlags = ExceptionInfo->ContextRecord->EFlags;
		context.Esp = ExceptionInfo->ContextRecord->Esp;
		context.SegSs = ExceptionInfo->ContextRecord->SegSs;

		if (target_memory_hex != NULL)
		{
			free(target_memory_hex);
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
		return EXCEPTION_CONTINUE_EXECUTION;	//EXCEPTION_CONTINUE_SEARCH
}

/*
	Debuggee 프로세스의 DLL 모듈들의 정보를 획득한다.
	(DLL Name / DLL Image BaseAddress / DLL Image Size)
*/
BOOL get_target_process_info(uint32_t* image_base, uint32_t* image_size)
{
	MODULEENTRY32 module_entry;
	HANDLE snapshot_handle;
	uint32_t loop_cnt = 0;

	module_entry.dwSize = sizeof(MODULEENTRY32);
	snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (snapshot_handle == INVALID_HANDLE_VALUE)
	{
		printf("get_target_process_info:: CreateToolhelp32Snapshot fail : %08X\n", GetLastError());
		finalize();
		return FALSE;
	}

	if (Module32First(snapshot_handle, &module_entry))
	{
		*image_base = (uint32_t)module_entry.modBaseAddr;
		*image_size = (uint32_t)module_entry.modBaseSize;
	}
	module_cnt++;

	do {
		module_cnt++;
	} while (Module32Next(snapshot_handle, &module_entry));

	module_list = (PMODULE_LIST)malloc(sizeof(MODULE_LIST) * module_cnt);
	Module32First(snapshot_handle, &module_entry);
	module_list[loop_cnt].image_base = (uint32_t)module_entry.modBaseAddr;
	module_list[loop_cnt].image_size = (uint32_t)module_entry.modBaseSize;
	wcscpy_s(module_list[loop_cnt].module_name, MODULE_MAX_SIZE, module_entry.szModule);
	loop_cnt++;

	do {
		module_list[loop_cnt].image_base = (uint32_t)module_entry.modBaseAddr;
		module_list[loop_cnt].image_size = (uint32_t)module_entry.modBaseSize;
		wcscpy_s(module_list[loop_cnt].module_name, MODULE_MAX_SIZE, module_entry.szModule);
		loop_cnt++;
	} while (Module32Next(snapshot_handle, &module_entry));

	CloseHandle(snapshot_handle);

	target_process_pe_parser();
	return TRUE;
}

/*
	Debuggee 프로세스의 DLL들의 Export Address Table 정보를 획득한다.
*/
void target_process_pe_parser()
{
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_EXPORT_DIRECTORY  eat_directory;

	UINT dll_cnt = 0;
	UINT export_cnt = 0;

	LPDWORD name_table, address_table;
	PWORD ordinal_table;
	WORD ordinal_number;

	char name_buffer[FUNCTION_MAX_SIZE];

	//	Test Log
	char buffer[512];
	HANDLE test_log_file;
	DWORD dwWrite;
	//

	test_log_file = CreateFileA("C:\\eat_map.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	// Test Log
	if (test_log_file == INVALID_HANDLE_VALUE)
	{
		memset(buffer, 0, sizeof(buffer));
		sprintf(buffer, "eat map file create fail [err=%08X]\r\n", GetLastError());
		WriteFile(test_log_file, buffer, strlen(buffer), &dwWrite, NULL);
		memset(buffer, 0, sizeof(buffer));
		return;
	}
	//
	memset(buffer, 0, sizeof(buffer));
	memset(name_buffer, 0, FUNCTION_MAX_SIZE);
	for (dll_cnt = 0; dll_cnt < module_cnt; dll_cnt++)
	{
		dos_header = (PIMAGE_DOS_HEADER)module_list[dll_cnt].image_base;
		nt_header = (PIMAGE_NT_HEADERS)((DWORD)dos_header + dos_header->e_lfanew);
		eat_directory = (PIMAGE_EXPORT_DIRECTORY)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD)dos_header);

		name_table = (DWORD)dos_header + eat_directory->AddressOfNames;
		ordinal_table = (DWORD)dos_header + eat_directory->AddressOfNameOrdinals;
		address_table = (DWORD)dos_header + eat_directory->AddressOfFunctions;

		winapi_info = (PWINAPI_EXPORT_FUNCTION)malloc(sizeof(WINAPI_EXPORT_FUNCTION) * eat_directory->NumberOfNames); 

	

		for (export_cnt = 0; export_cnt < eat_directory->NumberOfNames; export_cnt++)
		{
			winapi_info[export_cnt].dll_name = module_list[dll_cnt].module_name;

			if (eat_directory->AddressOfNames == 0 || eat_directory->AddressOfNameOrdinals == 0 || eat_directory->AddressOfFunctions == 0)
			{
				break;
			}
			
			if (!read_function_name((LPBYTE)((DWORD)dos_header + name_table[export_cnt]), name_buffer))
			{
				continue;
			}
			
			ordinal_number = ordinal_table[export_cnt];
			winapi_info[export_cnt].address = (DWORD)dos_header + address_table[ordinal_number];
			
			//	Test Log
			sprintf(buffer, "[%d] %ws %s %08X\r\n", export_cnt, winapi_info[export_cnt].dll_name,name_buffer ,winapi_info[export_cnt].address);
			WriteFile(test_log_file, buffer, strlen(buffer), &dwWrite, NULL);
			memset(buffer, 0, sizeof(buffer));
			//
		}
		//free(winapi_info);
	}
	MessageBoxA(NULL, "EAT Parsing END", " ", MB_OK);
}

BOOL read_function_name(LPBYTE name_table_address, char* name_buffer)
{
	UINT name_length = 0;

	memset(name_buffer, 0, FUNCTION_MAX_SIZE);

	if (name_table_address == NULL || name_buffer == NULL)
	{
		return FALSE;
	}
	//issue 001 
	if (strlen(name_table_address) > 256)
	{
		return FALSE;
	}
	name_buffer[name_length] = name_table_address[name_length];
	name_length++;

	while (name_table_address[name_length] != 0)
	{
		name_buffer[name_length] = name_table_address[name_length];
		name_length++;
	}
	
	return TRUE;
}