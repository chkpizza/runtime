#pragma once
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

#define MODULE_MAX_SIZE 256

typedef struct READABLE_MEMORY {
	uint32_t start_addr;
	uint32_t addr_size;
	uint32_t protect;
}READABLE_MEMORY_LIST, *PREADABLE_MEMORY_LIST;

typedef struct MODULE
{
	wchar_t module_name[MODULE_MAX_SIZE];
	uint32_t image_base;
	uint32_t image_size;
}MODULE_LIST, *PMODULE_LIST;

uint32_t get_pid();
uint32_t search_target_api(wchar_t* module_name, char* api_name);
void get_readable_memory_list(uint32_t image_base, uint32_t image_size, HANDLE target_process_handle);
void set_thread_context();



uint32_t target_pid; 
PREADABLE_MEMORY_LIST memory_list;
PMODULE_LIST module_list;
uint32_t readable_memory_count;
uint32_t module_cnt;