#pragma once
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

typedef struct READABLE_MEMORY {
	uint32_t start_addr;
	uint32_t addr_size;
}READABLE_MEMORY_LIST, *PREADABLE_MEMORY_LIST;

void set_thread_context();
uint32_t get_pid();
void get_readable_memory_list(uint32_t image_base, uint32_t image_size, HANDLE target_process_handle);

uint32_t target_pid; 
PREADABLE_MEMORY_LIST memory_list;
uint32_t readable_memory_count;
