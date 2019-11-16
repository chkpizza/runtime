#pragma once

#include "engine.h"
#include "extension_binder.h"

#define MODULE_MAX_SIZE 256
#define FUNCTION_MAX_SIZE 256

#define OS_VERSION_GET_FAIL		0

#define OS_WINDOWS7_MAJOR		6
#define OS_WINDOWS7_MINOR		1

#define OS_WINDOWS10_MAJOR		10
#define OS_WINDOWS10_MINOR		0

BOOL get_target_process_info(uint32_t* image_base, uint32_t* image_size);
void target_process_pe_parser();
BOOL read_function_name(LPBYTE name_table_address, char* name_buffer);
BOOL set_veh_debugger_config();
//BOOL disasm(PBYTE memory, UINT memory_address, uint32_t size);


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
DWORD veh_except_function_list[5];