#pragma once

#include <stdio.h>
#include <windows.h>

#define MULTI_SEARCH 1
#define SINGLE_SEARCH 0

DWORD* FindPattern(DWORD dwAddress, DWORD dwEndAddress, DWORD dwLen, BYTE* bMask, const char* szMask, BOOL search_type);		//x86 memory scanner 
BOOL bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);