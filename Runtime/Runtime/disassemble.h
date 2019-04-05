#pragma once

#include <uc\unicorn\unicorn.h>
#include <capstone\include\capstone.h>
#include <Windows.h>
#include <stdint.h>
#include "dr_debugger.h"

#pragma comment(lib, "unicorn_static.lib")
#pragma comment(lib, "capstone_static.lib")

BOOL read_target_process_memory();
BOOL get_target_process_info(uint32_t* image_base, uint32_t* image_size);
BOOL disasm(PBYTE memory, uint32_t memory_addr, uint32_t size);

uint32_t image_base;
uint32_t image_size;