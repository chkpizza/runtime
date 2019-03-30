#define _CRT_SECURE_NO_WARNINGS
#include "disassemble.h"
#pragma warning(disable:4996)
BOOL read_target_process_memory()
{
	return FALSE;
}
BOOL disasm(PVOID address, uint32_t size, uint32_t* convert_size)
{
	/*
	csh handle;
	cs_insn *insn;
	size_t count;
	char* abc = NULL;
	DWORD myInsert = 0;


	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	return -1;


	count = cs_disasm(handle, CODE, sizeof(CODE), 0x1000, 0, &insn);
	if (count > 0) {
	size_t j;
	for (j = 0; j < count; j++) {
	printf("%08X: %s  %s\n", (DWORD32)insn[j].address, insn[j].mnemonic,
	insn[j].op_str);

	}

	cs_free(insn, count);
	}
	else
	printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
	*/
	return FALSE;
}