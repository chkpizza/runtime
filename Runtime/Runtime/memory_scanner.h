#pragma once

#include <stdio.h>
#include <windows.h>
#include <stdint.h>

#define MULTI_SEARCH 1
#define SINGLE_SEARCH 0

DWORD* FindPattern(DWORD dwAddress, DWORD dwEndAddress, DWORD dwLen, BYTE* bMask, const char* szMask, BOOL search_type);		//x86 memory scanner 
BOOL bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);

uint32_t execute_memory_size;

typedef struct {
	uint32_t base_address;
	uint32_t address_size;
}EXECUTE_MEMORY_DATA, *PEXECUTE_MEMORY_DATA;