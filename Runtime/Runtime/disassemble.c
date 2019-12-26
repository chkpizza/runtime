#include "disassemble.h"
#include "dr_debugger.h"

#pragma warning(disable:4996)

BOOL read_target_process_memory()
{
	HANDLE target_process_handle;
	uint32_t target_image_base;
	uint32_t target_image_size;
	uint32_t loop_count;
	uint32_t read_size;
	PBYTE target_memory_hex;
	

	target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, get_pid());
	if (target_process_handle == NULL)
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


BOOL get_target_process_info(uint32_t* image_base, uint32_t* image_size)
{
	MODULEENTRY32 module_entry;
	HANDLE snapshot_handle;
	uint32_t loop_cnt = 0;

	module_entry.dwSize = sizeof(MODULEENTRY32);
	snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, get_pid());
	if (snapshot_handle == INVALID_HANDLE_VALUE)
	{
		printf("get_target_process_info:: CreateToolhelp32Snapshot fail : %08X\n", GetLastError());
		return FALSE;
	}

	if (Module32First(snapshot_handle, &module_entry))
	{
		*image_base = (uint32_t)module_entry.modBaseAddr;
		*image_size = (uint32_t)module_entry.modBaseSize;
	}
	module_cnt++;

	do {
		module_cnt++;
	} while (Module32Next(snapshot_handle, &module_entry));

	module_list = (PMODULE_LIST)malloc(sizeof(MODULE_LIST) * module_cnt);
	Module32First(snapshot_handle, &module_entry);
	module_list[loop_cnt].image_base = (uint32_t)module_entry.modBaseAddr;
	module_list[loop_cnt].image_size = (uint32_t)module_entry.modBaseSize;
	wcscpy_s(module_list[loop_cnt].module_name, MODULE_MAX_SIZE, module_entry.szModule);
	loop_cnt++;

	do {
		module_list[loop_cnt].image_base = (uint32_t)module_entry.modBaseAddr;
		module_list[loop_cnt].image_size = (uint32_t)module_entry.modBaseSize;
		wcscpy_s(module_list[loop_cnt].module_name, MODULE_MAX_SIZE, module_entry.szModule);
		loop_cnt++;
	} while (Module32Next(snapshot_handle, &module_entry));


	for (loop_cnt = 0; loop_cnt < module_cnt; loop_cnt++)
	{
		printf("[%d] %08X - %08X : %ws\n", loop_cnt + 1, module_list[loop_cnt].image_base, (module_list[loop_cnt].image_base + module_list[loop_cnt].image_size), module_list[loop_cnt].module_name);
	}

	CloseHandle(snapshot_handle);

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
			
			if (!(cmd_count % 100))
			{
				system("pause");
				break;	//юс╫ц break
			}
			
			/*
			if ((cmd_count % 100) == 0)
			{
				system("pause");
			}
			*/
			printf("[%d] %08X: %s %s\n", insn[cmd_count].size, (uint32_t)insn[cmd_count].address, insn[cmd_count].mnemonic, insn[cmd_count].op_str);
			
		}
	}
	return TRUE;
}