#pragma once
#include <capstone\include\capstone.h>
#include <uc\unicorn\unicorn.h>
#include <Windows.h>
#include <stdint.h>

#pragma comment(lib, "unicorn_static.lib")
#pragma comment(lib, "capstone_static.lib")

BOOL read_target_process_memory();
BOOL disasm(PVOID address, uint32_t size, uint32_t* convert_size);

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"