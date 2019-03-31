/*
	memory scan module

	MULTI_SEARCH   == 1
	SINGLE_SEARCH  == 0
*/

#include "memory_scanner.h"

BOOL search_crash = FALSE;
DWORD global_var = 0;

DWORD* FindPattern(DWORD dwAddress, DWORD dwEndAddress, DWORD dwLen, BYTE* bMask, const char* szMask, BOOL search_type)
{
	DWORD loop = 0;
	int tmp = 0;
	DWORD cnt = 0;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD scan_address = 0;
	DWORD return_address = 0;
	DWORD result_address = 0;

	static DWORD pattern_address[20] = { 0, };

	char read_buffer[512];

	memset(pattern_address, 0, sizeof(pattern_address));
	memset(read_buffer, 0, 512);
	memset(&mbi, 0, sizeof(mbi));

	search_crash = TRUE;

	scan_address = dwAddress;
	global_var = 0;

	while (scan_address <= dwEndAddress)
	{
		memset(&mbi, 0, sizeof(mbi));
		VirtualQuery((LPVOID)(ULONG_PTR)scan_address, &mbi, sizeof(mbi));

		if (mbi.State != MEM_COMMIT) {
			scan_address = scan_address + mbi.RegionSize;
			continue;
		}
		if ((mbi.Protect == PAGE_NOACCESS) || (mbi.Protect == PAGE_GUARD) || (mbi.Protect == PAGE_WRITECOPY) || (mbi.Protect == PAGE_NOCACHE)) {
			scan_address = scan_address + mbi.RegionSize;
			continue;
		}
		if ((mbi.Protect == (PAGE_READWRITE | PAGE_GUARD)))
		{
			scan_address = scan_address + mbi.RegionSize;
			continue;
		}

		if (dwLen < mbi.RegionSize)
		{
			for (loop = 0; loop < dwLen; loop++) {
				tmp++;
				if (bCompare((BYTE*)(scan_address + loop), bMask, szMask)) {
					return_address = scan_address + loop;    // 일치
					pattern_address[cnt] = return_address;
					cnt++;
					if (search_type == SINGLE_SEARCH)
					{
						return pattern_address;
					}
					global_var++;
				}
				else
				{
					if (search_crash == FALSE)
					{
						return NULL;
					}
				}
			}
		}
		else
		{
			for (loop = 0; loop < (mbi.RegionSize - strlen((char*)bMask)); loop++) {
				tmp++;
				if (bCompare((BYTE*)(scan_address + loop), bMask, szMask)) {
					return_address = scan_address + loop;    // 일치
					pattern_address[cnt] = return_address;
					cnt++;
					if (search_type == SINGLE_SEARCH)
					{
						return pattern_address;
					}
				}
				else
				{
					if (search_crash == FALSE)
					{
						return NULL;
					}
				}
			}
		}
		scan_address = scan_address + mbi.RegionSize;
	}

	if (pattern_address[0] != 0)
	{
		return pattern_address;
	}
	result_address = loop;

	return NULL;
}

BOOL bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	BOOL bRet = FALSE;
	MEMORY_BASIC_INFORMATION mbi;

	memset(&mbi, 0, sizeof(mbi));

	VirtualQuery((LPVOID)(ULONG_PTR)pData, &mbi, sizeof(mbi));
	if (mbi.State == MEM_FREE)
	{
		search_crash = FALSE;
		return FALSE;
	}
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return bRet;

	return (*szMask) == NULL;
}
