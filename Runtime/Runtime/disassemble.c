#include "disassemble.h"

#pragma warning(disable:4996)

BOOL read_target_process_memory()
{
	HANDLE target_process_handle;
	uint32_t target_image_base;
	uint32_t target_image_size;
	uint32_t loop_count;
	uint32_t read_size;
	PBYTE target_memory_hex;

	get_pid();
	target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
	if (target_process_handle == INVALID_HANDLE_VALUE)
	{
		printf("read_target_process_memory:: OpenProcess fail : %08X\n", GetLastError());
		return FALSE;
	}

	if (get_target_process_info(&target_image_base, &target_image_size))
	{
		printf("target process info success\n");
	}

	get_readable_memory_list(target_image_base, target_image_size, target_process_handle);
	loop_count = 0;

	while (loop_count < readable_memory_count)
	{
		if (memory_list[loop_count].protect == PAGE_EXECUTE_READ || memory_list[loop_count].protect == PAGE_EXECUTE_READWRITE ||
			memory_list[loop_count].protect == PAGE_EXECUTE_WRITECOPY)
		{
			target_memory_hex = (PBYTE)malloc(memory_list[loop_count].addr_size);
			memset(target_memory_hex, 0, memory_list[loop_count].addr_size);
			ReadProcessMemory(target_process_handle, (LPVOID)memory_list[loop_count].start_addr, target_memory_hex, memory_list[loop_count].addr_size, &read_size);
			disasm(target_memory_hex, memory_list[loop_count].start_addr, memory_list[loop_count].addr_size);
			free(target_memory_hex);
		}
		loop_count++;
	}
	return TRUE;
}


BOOL disasm(PBYTE memory, uint32_t memory_addr, uint32_t size)
{
	
	csh handle;
	cs_insn *insn;
	size_t count;
	size_t cmd_count = 0;
	uint32_t next_addr = memory_addr;
	uint32_t offset = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	{
		return FALSE;
	}

	count = cs_disasm(handle, (const uint8_t*)(memory + offset), size, memory_addr + offset, 0, &insn);
	if (count > 0)
	{
		for (cmd_count = 0; cmd_count < count; cmd_count++)
		{
			/*
			if (!(cmd_count % 100))
			{
				system("pause");
				system("cls");
			}
			printf("[%d] %08X: %s %s\n", insn[cmd_count].size, (uint32_t)insn[cmd_count].address, insn[cmd_count].mnemonic, insn[cmd_count].op_str);
			*/
		}
	}

	return TRUE;
}