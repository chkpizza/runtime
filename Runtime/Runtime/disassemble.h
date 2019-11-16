#pragma once

#include <capstone\include\capstone.h>
#include <uc\unicorn\unicorn.h>
#include <Windows.h>
#include <stdint.h>
#include "dr_debugger.h"

#ifdef _WIN64
#pragma comment(lib, "capstone_static_x64.lib")

#else
#pragma comment(lib, "capstone_static.lib")

#endif // _WIN64

#pragma comment(lib, "unicorn_static.lib")

BOOL read_target_process_memory();
BOOL get_target_process_info(uint32_t* image_base, uint32_t* image_size);
BOOL disasm(PBYTE memory, uint32_t memory_addr, uint32_t size);

typedef struct MODULE
{
	wchar_t module_name[MODULE_MAX_SIZE];
	UINT image_base;
	UINT image_size;
}MODULE_LIST, *PMODULE_LIST;

typedef struct EXPORT_FUNCTION
{
	wchar_t* dll_name;
	UINT address;
	char name[FUNCTION_MAX_SIZE];
}WINAPI_EXPORT_FUNCTION, *PWINAPI_EXPORT_FUNCTION;

uint32_t module_cnt;
uint32_t image_base;
uint32_t image_size;
PMODULE_LIST module_list;
PWINAPI_EXPORT_FUNCTION winapi_info;
