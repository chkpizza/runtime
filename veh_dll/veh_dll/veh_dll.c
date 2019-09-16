#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <LM.h>
#include "veh_debugger.h"

#pragma comment(lib, "netapi32.lib")

#define CODE "\x8B\xFF\x55\x8B\xEC\x83\x3D\x74\x9A\x0A\x76\x00"
#define OS_VERSION_GET_FAIL		0

#define OS_WINDOWS7_MAJOR		6
#define OS_WINDOWS7_MINOR		1

#define OS_WINDOWS10_MAJOR		10
#define OS_WINDOWS10_MINOR		0

void start();
int check_running_os();
BOOL insert_veh_win10();
BOOL insert_veh_win7();
LONG WINAPI first_veh(
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
			insert_veh_win7();
			MessageBoxA(NULL, "insert veh windows7", " ", MB_OK);
			break;

		case OS_WINDOWS10_MAJOR:
			insert_veh_win10();
			MessageBoxA(NULL, "insert veh windows10", " ", MB_OK);
			break;

		default:
			break;
		}

		get_target_process_info(&image_base, &image_size);

		while (1)
		{
			i++;
			Sleep(1000);
		}
	}
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

LONG WINAPI first_veh(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		memset(tmp_buffer, 0, 512);
		step_count++;


		sprintf(tmp_buffer, "exception addr : %08X\neip : %08X\nexception code : %08X\n ESP : %08X EBP : %08X ECX : %08X EDX : %08X EDI : %08X ESI : %08X\n",
			ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Eip,
			ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx, 
			ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Esi);

		ExceptionInfo->ContextRecord->EFlags |= 0x100;
		ExceptionInfo->ContextRecord->Dr0 = 0;
		ExceptionInfo->ContextRecord->Dr6 = 0;
		ExceptionInfo->ContextRecord->Dr7 = 0;
		ExceptionInfo->ContextRecord->ContextFlags |= CONTEXT_DEBUG_REGISTERS;

		if (MessageBoxA(NULL, tmp_buffer, "[ESCAPE]", MB_OKCANCEL) == IDCANCEL)
		{
			ExceptionInfo->ContextRecord->EFlags ^= 0x100;
			MessageBoxA(NULL, "escape single step", " escape", MB_OK);
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
		return EXCEPTION_CONTINUE_SEARCH;
	
}
BOOL insert_veh_win10()
{
	DWORD _LdrpVectorHandlerList;
	FARPROC _RtlAllocateHeap;
	FARPROC _RtlEncodePointer;
	FARPROC _RtlAddVectoredExceptionHandler;
	DWORD _LdrProtectMrdata = 0;
	HMODULE ntdll;
	DWORD* heap;
	DWORD heap_handle;
	DWORD encode_pointer;
	DWORD cookie_value;

	DWORD insert_func = (DWORD)first_veh;
	DWORD inner_function_addr = 0;
	byte inner_add_veh[100] = { 0, };
	byte handler_list[100] = { 0, };
	byte cookie[100] = { 0, };
	DWORD tmp_convert_var = 0;
	DWORD calc_call = 0;
	DWORD convert_handler_list = 0;
						
	ntdll = LoadLibraryA("ntdll.dll");
	_RtlAllocateHeap = GetProcAddress(ntdll, "RtlAllocateHeap");
	_RtlAddVectoredExceptionHandler = GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");
	_RtlEncodePointer = GetProcAddress(ntdll, "RtlEncodePointer");

	memcpy(inner_add_veh, (byte*)_RtlAddVectoredExceptionHandler + 14, 20);

	tmp_convert_var = (DWORD)inner_add_veh[3];
	tmp_convert_var = tmp_convert_var << 24;
	inner_function_addr = tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[2];
	tmp_convert_var = tmp_convert_var << 16;
	inner_function_addr = inner_function_addr + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[1];
	tmp_convert_var = tmp_convert_var << 8;
	inner_function_addr = inner_function_addr + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[0];
	inner_function_addr = inner_function_addr + tmp_convert_var;

	calc_call = (DWORD32)_RtlAddVectoredExceptionHandler + 0x0D + inner_function_addr + 5;


	memcpy(handler_list, (byte*)calc_call + 0x88, 4);	

	tmp_convert_var = (DWORD)handler_list[3];
	tmp_convert_var = tmp_convert_var << 24;
	_LdrpVectorHandlerList = tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[2];
	tmp_convert_var = tmp_convert_var << 16;
	_LdrpVectorHandlerList = _LdrpVectorHandlerList + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[1];
	tmp_convert_var = tmp_convert_var << 8;
	_LdrpVectorHandlerList = _LdrpVectorHandlerList + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[0];
	_LdrpVectorHandlerList = _LdrpVectorHandlerList + tmp_convert_var;


	memcpy(cookie, (byte*)calc_call + 0x60, 4);

	tmp_convert_var = (DWORD)cookie[3];
	tmp_convert_var = tmp_convert_var << 24;
	cookie_value = tmp_convert_var;

	tmp_convert_var = (DWORD)cookie[2];
	tmp_convert_var = tmp_convert_var << 16;
	cookie_value = cookie_value + tmp_convert_var;

	tmp_convert_var = (DWORD)cookie[1];
	tmp_convert_var = tmp_convert_var << 8;
	cookie_value = cookie_value + tmp_convert_var;

	tmp_convert_var = (DWORD)cookie[0];
	cookie_value = cookie_value + tmp_convert_var;

	memset(inner_add_veh, 0, sizeof(inner_add_veh));
	memcpy(inner_add_veh, (byte*)calc_call + 0x90, 4);

	tmp_convert_var = 0;
	tmp_convert_var = (DWORD)inner_add_veh[3];
	tmp_convert_var = tmp_convert_var << 24;
	_LdrProtectMrdata = _LdrProtectMrdata + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[2];
	tmp_convert_var = tmp_convert_var << 16;
	_LdrProtectMrdata = _LdrProtectMrdata + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[1];
	tmp_convert_var = tmp_convert_var << 8;
	_LdrProtectMrdata = _LdrProtectMrdata + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[0];
	_LdrProtectMrdata = _LdrProtectMrdata + tmp_convert_var;

	_LdrProtectMrdata = _LdrProtectMrdata + calc_call + 0x8f + 5;


	__asm {
		push eax
		push ecx
		mov eax, fs:[0x18]
		mov eax, [eax + 0x30]
		mov ecx, [eax + 0x18]
		mov heap_handle, ecx
		pop ecx
		pop eax
	}

	heap = _RtlAllocateHeap(heap_handle, 0, 0x10);
	memset(heap, 0, 0x10);
	encode_pointer = _RtlEncodePointer(insert_func);

	__asm {
		push esi
		push eax
		push ecx
		push edi
		push ebx

		mov esi, heap

		mov dword ptr[esi + 0x08], 1
		mov eax, encode_pointer
		mov dword ptr [esi+0x0C], eax

		push 0
		mov ebx, _LdrpVectorHandlerList
		call _LdrProtectMrdata

		mov edi, [ebx]
		lock bts dword ptr [edi], 0


		mov ecx, 0
		mov eax, dword ptr fs:[0x30]
		add ecx, 2
		add eax, 0x28
		lock bts [eax], ecx

		lea edi, dword ptr [ebx+4]
		mov eax, dword ptr [edi]

		mov dword ptr [esi], eax
		mov dword ptr [esi+4], edi
		mov dword ptr [eax+4], esi
		mov dword ptr [edi], esi

		mov edi, dword ptr [ebx]
		xor ecx, ecx
		mov eax, 1
		lock cmpxchg [edi], ecx	

		push 1
		call _LdrProtectMrdata

		pop ebx
		pop edi
		pop ecx
		pop eax
		pop esi
	}
	MessageBoxA(NULL, "OS/Windows 10 VEH inject success", "successful", MB_OK);
}

BOOL insert_veh_win7()
{
	DWORD _LdrpVectorHandlerList;
	FARPROC _RtlAllocateHeap;
	FARPROC _RtlEncodePointer;
	FARPROC _RtlAddVectoredExceptionHandler;
	HMODULE ntdll;
	DWORD* heap;
	DWORD heap_handle;
	DWORD encode_pointer;

	DWORD insert_func = (DWORD)first_veh;
	DWORD inner_function_addr = 0;
	byte inner_add_veh[100] = { 0, };
	byte handler_list[100] = { 0, };
	DWORD tmp_convert_var = 0;
	DWORD calc_call = 0;
	DWORD convert_handler_list = 0;

	ntdll = LoadLibraryA("ntdll.dll");
	_RtlAllocateHeap = GetProcAddress(ntdll, "RtlAllocateHeap");
	_RtlEncodePointer = GetProcAddress(ntdll, "RtlEncodePointer");
	_RtlAddVectoredExceptionHandler = GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");

	memcpy(inner_add_veh, (byte*)_RtlAddVectoredExceptionHandler + 14, 20);

	tmp_convert_var = (DWORD)inner_add_veh[3];
	tmp_convert_var = tmp_convert_var << 24;
	inner_function_addr = tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[2];
	tmp_convert_var = tmp_convert_var << 16;
	inner_function_addr = inner_function_addr + tmp_convert_var;


	tmp_convert_var = (DWORD)inner_add_veh[1];
	tmp_convert_var = tmp_convert_var << 8;
	inner_function_addr = inner_function_addr + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[0];
	inner_function_addr = inner_function_addr + tmp_convert_var;

	calc_call = (DWORD32)_RtlAddVectoredExceptionHandler + 0x0D + inner_function_addr + 5;

	memcpy(handler_list, (byte*)calc_call + 0x3A, 4);	//77F9723C

	tmp_convert_var = (DWORD)handler_list[3];
	tmp_convert_var = tmp_convert_var << 24;
	_LdrpVectorHandlerList = tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[2];
	tmp_convert_var = tmp_convert_var << 16;
	_LdrpVectorHandlerList = _LdrpVectorHandlerList + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[1];
	tmp_convert_var = tmp_convert_var << 8;
	_LdrpVectorHandlerList = _LdrpVectorHandlerList + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[0];
	_LdrpVectorHandlerList = _LdrpVectorHandlerList + tmp_convert_var;
	//0x778C723C
	__asm {
		push eax
		push ecx
		mov eax, fs:[0x18]
		mov eax, [eax+0x30]
		mov ecx, [eax+0x18]
		mov heap_handle, ecx
		pop ecx
		pop eax
	}

	heap = _RtlAllocateHeap(heap_handle, 0, 0x10);
	memset(heap, 0, 0x10);
	encode_pointer = _RtlEncodePointer(insert_func);

	__asm {
		push ebx
		push esi
		push ecx
		push edx
		push edi

		mov esi, heap
		mov eax, _LdrpVectorHandlerList
		mov edi, _LdrpVectorHandlerList
		add edi, 4

		mov dword ptr [esi+8], 1
		mov ebx, encode_pointer
		mov dword ptr [esi+0x0C], ebx
		//mov dword ptr [esi+0x0C], encode_pointer
		lock bts dword ptr [eax], 0
		
		cmp dword ptr [edi], edi

// VEH가 설치되어 있지 않은 경우
		mov ecx, dword ptr fs:[0x18]
		mov eax, 0
		mov ecx, dword ptr [ecx+0x30]
		add eax, 2
		add ecx, 0x28
		lock bts dword ptr [ecx], eax

		mov eax, dword ptr [edi]
		mov dword ptr [esi], eax	//AllocateHeap + 0 = _LdrpVectorHandlerList+4
		mov dword ptr [esi+4], edi	//AllocateHeap + 4 = _LdrpVectorHandlerList+4
		mov dword ptr [eax+4], esi	//_LdrpVectorHandlerList+8 = AllocateHeap
		mov dword ptr [edi], esi	//_LdrpVectorHandlerList+4 = AllocateHeap
// VEH가 설치되어 있지 않은 경우
		or ecx, 0xFFFFFFFF
		mov eax, _LdrpVectorHandlerList
		lock xadd dword ptr [eax], ecx

		pop edi
		pop edx
		pop ecx
		pop esi
		pop ebx
	}
}



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
	//
	//	Debuggee Process EAT Parsing 
	//
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

	test_log_file = CreateFileA("C:\\EAT_TEST.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	// Test Log
	if (test_log_file == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "CreateFile Fail", " ", MB_OK);
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
				//	Test Log
				sprintf(buffer, "[%d] %ws => zero", export_cnt, winapi_info[export_cnt].dll_name);
				MessageBoxA(NULL, buffer, " ", MB_OK);
				//
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
			//
		}
	}
	MessageBoxA(NULL, "EAT Parsing END", " ", MB_OK);
}

/*
	//
	//	EAT Function Name Read
	//
*/
BOOL read_function_name(LPBYTE name_table_address, char* name_buffer)
{
	UINT name_length = 0;

	memset(name_buffer, 0, FUNCTION_MAX_SIZE);

	if (name_table_address == NULL || name_buffer == NULL)
	{
		return FALSE;
	}

	name_buffer[name_length] = name_table_address[name_length];
	name_length++;

	while (name_table_address[name_length] != NULL)
	{
		name_buffer[name_length] = name_table_address[name_length];
		name_length++;
	}

	return TRUE;
}