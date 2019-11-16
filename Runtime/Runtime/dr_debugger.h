#pragma once
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#define MODULE_MAX_SIZE 256
#define FUNCTION_MAX_SIZE 256

typedef struct READABLE_MEMORY {
	uint32_t start_addr;
	uint32_t addr_size;
	uint32_t protect;
}READABLE_MEMORY_LIST, *PREADABLE_MEMORY_LIST;

uint32_t get_pid();
//uint32_t search_target_api(wchar_t* module_name, char* api_name);
void get_readable_memory_list(uint32_t image_base, uint32_t image_size, HANDLE target_process_handle);
void set_thread_context();
void inject_vehdbg_library();


PREADABLE_MEMORY_LIST memory_list;
uint32_t readable_memory_count;
