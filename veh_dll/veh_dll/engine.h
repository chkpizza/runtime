#pragma once

#include <capstone\include\capstone.h>
#include <uc\unicorn\unicorn.h>
#include <Windows.h>
#include <stdint.h>
#include <LM.h>
#include <TlHelp32.h>

#pragma comment(lib, "netapi32.lib")

#pragma warning (disable:4996)

#ifdef _WIN64
#pragma comment(lib, "capstone_static_x64.lib")

#else
#pragma comment(lib, "capstone_static.lib")

#endif // _WIN64

#pragma comment(lib, "unicorn_static.lib")

#define MAXIMUM_OPCODE_SIZE 15
#define EXCEPT_FUNCTION_COUNT 1
#define EXCEPT_RTL_ENTER_CRITICAL_SECTION "RtlEnterCriticalSection"
#define EXCEPT_RTL_ENTER_CRITICAL_SECTION_DLL "ntdll.dll"

#define OBJECT_NAME "Local\\INTERPE"

typedef struct _MOD_CONTEXT {
	DWORD ContextFlags;

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	FLOATING_SAVE_AREA FloatSave;

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;              // MUST BE SANITIZED
	DWORD   EFlags;             // MUST BE SANITIZED
	DWORD   Esp;
	DWORD   SegSs;

	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];

} MOD_CONTEXT;

BOOL insert_veh_win10(DWORD veh_handler);
BOOL insert_veh_win7(DWORD veh_handler);
DWORD convert_endian(byte* original);
BOOL disasm(UINT memory_address, DWORD* next_line);
BOOL write_log(char* log_text);
//DWORD get_veh_except_function_address(char* except_function_dll ,char* except_function_name);
UINT get_veh_except_function_address(DWORD* except_function_array);

void init();
void sender();
void receiver();

void step_rewind(MOD_CONTEXT* rewind_context, PCONTEXT current_context);
void step_run(DWORD break_point_address, PCONTEXT current_context);
void step_over(PCONTEXT current_context, DWORD current_address);

BOOL heap_pooling(LPVOID pooling_address);
BOOL finalize();

MOD_CONTEXT context;
static HANDLE log_file_handle = NULL;

HANDLE mapping_handle;
char* shared_memory;

char tmp_buffer[512];
int trace_command;