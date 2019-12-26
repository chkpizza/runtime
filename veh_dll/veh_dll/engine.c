#include "engine.h"

PDWORD allocate_tracker = NULL;
UINT heap_size = 0;

/*
	Windows 10 32bit 용 Vectored Exception Handler Injection 함수
	VEH Debugger Handler를 First Handler로 Injection 한다.
*/
BOOL insert_veh_win10(DWORD veh_handler)
{
	DWORD _LdrpVectorHandlerList;
	FARPROC _RtlAllocateHeap;
	FARPROC _RtlEncodePointer;
	FARPROC _RtlAddVectoredExceptionHandler;
	DWORD _LdrProtectMrdata = 0;
	HMODULE ntdll;
	DWORD* heap;
	DWORD heap_handle;
	DWORD encode_pointer;

	DWORD insert_func = (DWORD)veh_handler;
	DWORD inner_function_address = 0;
	byte inner_add_veh[100] = { 0, };
	byte handler_list[100] = { 0, };
	DWORD calc_call = 0;

	ntdll = LoadLibraryA("ntdll.dll");
	_RtlAllocateHeap = GetProcAddress(ntdll, "RtlAllocateHeap");
	_RtlAddVectoredExceptionHandler = GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");
	_RtlEncodePointer = GetProcAddress(ntdll, "RtlEncodePointer");

	memcpy(inner_add_veh, (byte*)_RtlAddVectoredExceptionHandler + 14, 20);

	inner_function_address = convert_endian(inner_add_veh);

	calc_call = (DWORD32)_RtlAddVectoredExceptionHandler + 0x0D + inner_function_address + 5;

	memcpy(handler_list, (byte*)calc_call + 0x88, 4);	//_LdrpVectorHandlerList offset == 0x88

	_LdrpVectorHandlerList = convert_endian(handler_list);

	memset(inner_add_veh, 0, sizeof(inner_add_veh));
	memcpy(inner_add_veh, (byte*)calc_call + 0x90, 4);	//_LdrProtectMrData function offset == 0x90

	_LdrProtectMrdata = convert_endian(inner_add_veh);
	_LdrProtectMrdata = _LdrProtectMrdata + calc_call + 0x8f + 5;

	__asm {
		push eax
		push ecx
		mov eax, fs:[0x18]
		mov eax, [eax + 0x30]
		mov ecx, [eax + 0x18]
		mov heap_handle, ecx
		pop ecx
		pop eax
	}

	heap = _RtlAllocateHeap(heap_handle, 0, 0x10);
	memset(heap, 0, 0x10);
	encode_pointer = _RtlEncodePointer(insert_func);

	__asm {
		push esi
		push eax
		push ecx
		push edi
		push ebx

		mov esi, heap

		mov dword ptr[esi + 0x08], 1
		mov eax, encode_pointer
		mov dword ptr[esi + 0x0C], eax

		push 0
		mov ebx, _LdrpVectorHandlerList
		call _LdrProtectMrdata

		mov edi, [ebx]
		lock bts dword ptr[edi], 0

		mov ecx, 0
		mov eax, dword ptr fs : [0x30]
		add ecx, 2
		add eax, 0x28
		lock bts[eax], ecx

		lea edi, dword ptr[ebx + 4]
		mov eax, dword ptr[edi]

		mov dword ptr[esi], eax
		mov dword ptr[esi + 4], edi
		mov dword ptr[eax + 4], esi
		mov dword ptr[edi], esi

		mov edi, dword ptr[ebx]
		xor ecx, ecx
		mov eax, 1
		lock cmpxchg[edi], ecx

		push 1
		call _LdrProtectMrdata

		pop ebx
		pop edi
		pop ecx
		pop eax
		pop esi
	}
	MessageBoxA(NULL, "OS/Windows 10 VEH inject success", "successful", MB_OK);
}

/*
	Windows 7 32bit 용 Vectored Exception Handler Injection 함수
	VEH Debugger Handler를 First Handler로 Injection 한다.
*/
BOOL insert_veh_win7(DWORD veh_handler)
{
	DWORD _LdrpVectorHandlerList;
	FARPROC _RtlAllocateHeap;
	FARPROC _RtlEncodePointer;
	FARPROC _RtlAddVectoredExceptionHandler;
	HMODULE ntdll;
	DWORD* heap;
	DWORD heap_handle;
	DWORD encode_pointer;

	DWORD insert_func = (DWORD)veh_handler;
	DWORD inner_function_address = 0;
	byte inner_add_veh[100] = { 0, };
	byte handler_list[100] = { 0, };
	DWORD calc_call = 0;

	ntdll = LoadLibraryA("ntdll.dll");
	_RtlAllocateHeap = GetProcAddress(ntdll, "RtlAllocateHeap");
	_RtlEncodePointer = GetProcAddress(ntdll, "RtlEncodePointer");
	_RtlAddVectoredExceptionHandler = GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");

	memcpy(inner_add_veh, (byte*)_RtlAddVectoredExceptionHandler + 14, 20);

	inner_function_address = convert_endian(inner_add_veh);

	calc_call = (DWORD32)_RtlAddVectoredExceptionHandler + 0x0D + inner_function_address + 5;

	memcpy(handler_list, (byte*)calc_call + 0x3A, 4);	//77F9723C

	_LdrpVectorHandlerList = convert_endian(handler_list);

	__asm {
		push eax
		push ecx
		mov eax, fs:[0x18]
		mov eax, [eax + 0x30]
		mov ecx, [eax + 0x18]
		mov heap_handle, ecx
		pop ecx
		pop eax
	}

	heap = _RtlAllocateHeap(heap_handle, 0, 0x10);
	memset(heap, 0, 0x10);
	encode_pointer = _RtlEncodePointer(insert_func);

	__asm {
		push ebx
		push esi
		push ecx
		push edx
		push edi

		mov esi, heap
		mov eax, _LdrpVectorHandlerList
		mov edi, _LdrpVectorHandlerList
		add edi, 4

		mov dword ptr[esi + 8], 1
		mov ebx, encode_pointer
		mov dword ptr[esi + 0x0C], ebx
		//mov dword ptr [esi+0x0C], encode_pointer
		lock bts dword ptr[eax], 0

		cmp dword ptr[edi], edi

		// VEH가 설치되어 있지 않은 경우
		mov ecx, dword ptr fs : [0x18]
		mov eax, 0
		mov ecx, dword ptr[ecx + 0x30]
		add eax, 2
		add ecx, 0x28
		lock bts dword ptr[ecx], eax

		mov eax, dword ptr[edi]
		mov dword ptr[esi], eax	//AllocateHeap + 0 = _LdrpVectorHandlerList+4
		mov dword ptr[esi + 4], edi	//AllocateHeap + 4 = _LdrpVectorHandlerList+4
		mov dword ptr[eax + 4], esi	//_LdrpVectorHandlerList+8 = AllocateHeap
		mov dword ptr[edi], esi	//_LdrpVectorHandlerList+4 = AllocateHeap
							// VEH가 설치되어 있지 않은 경우
		or ecx, 0xFFFFFFFF
		mov eax, _LdrpVectorHandlerList
		lock xadd dword ptr[eax], ecx

		pop edi
		pop edx
		pop ecx
		pop esi
		pop ebx
	}

	MessageBoxA(NULL, "OS/Windows 7 VEH inject success", "successful", MB_OK);
}

DWORD convert_endian(byte* original)
{
	DWORD convert_result = 0;
	DWORD tmp_convert_value = 0;

	tmp_convert_value = (DWORD)original[3];
	tmp_convert_value = tmp_convert_value << 24;
	convert_result = tmp_convert_value;

	tmp_convert_value = (DWORD)original[2];
	tmp_convert_value = tmp_convert_value << 16;
	convert_result = convert_result + tmp_convert_value;

	tmp_convert_value = (DWORD)original[1];
	tmp_convert_value = tmp_convert_value << 8;
	convert_result = convert_result + tmp_convert_value;

	tmp_convert_value = (DWORD)original[0];
	convert_result = convert_result + tmp_convert_value;

	return convert_result;
}



BOOL disasm(UINT memory_addr, DWORD* next_line)
{

	csh handle;
	cs_insn *insn;
	size_t count;
	size_t cmd_count = 0;
	uint32_t next_addr = memory_addr;
	uint32_t offset = 0;
	DWORD read_memory_size = 0;
	char buffer[256];
	BYTE read_memory_buffer[15];

	if (log_file_handle == NULL)
	{
		log_file_handle = CreateFileA("C:\\asm_test.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (log_file_handle == INVALID_HANDLE_VALUE)
		{
			MessageBoxA(NULL, "test_asm_file.txt create fail", " ", MB_OK);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	memset(buffer, 0, sizeof(buffer));
	memset(read_memory_buffer, 0, 15);

	if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)memory_addr, read_memory_buffer, 15, &read_memory_size))
	{
		MessageBoxA(NULL, "disasm::ReadProcessMemory() fail", " ", MB_OK);
		return FALSE;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	{
		return FALSE;
	}
	count = cs_disasm(handle, (const uint8_t*)(read_memory_buffer + offset), MAXIMUM_OPCODE_SIZE, memory_addr + offset, 0, &insn);
	if (count > 0)
	{
		for (cmd_count = 0; cmd_count < count; cmd_count++)
		{
			sprintf(buffer, "[%d] %08X: %s %s next : %08X\r\n", insn[cmd_count].size, (uint32_t)insn[cmd_count].address, insn[cmd_count].mnemonic, insn[cmd_count].op_str, (uint32_t)insn[cmd_count + 1].address);
			if (!strcmp(insn[cmd_count].mnemonic, "call"))
			{
				MessageBoxA(NULL, buffer, "find call", MB_OK);
				*next_line = (uint32_t)insn[cmd_count + 1].address;
			}
			write_log(buffer);
			break;
		}
	}

	return TRUE;
}

void init()
{
	mapping_handle = OpenFileMappingA
	(
		FILE_MAP_READ | FILE_MAP_WRITE,
		FALSE,
		OBJECT_NAME
	);

	shared_memory = (char*)MapViewOfFile
	(
		mapping_handle,
		PAGE_READONLY,
		0,
		0,
		0
	);
}
void sender()
{
	strcpy(shared_memory, tmp_buffer);
	receiver();
}
void receiver()
{
	while (1)
	{
		if (!strcmp(shared_memory, "step_over"))
		{
			trace_command = 1;
			break;
		}
		else if (!strcmp(shared_memory, "step_rewind"))
		{
			trace_command = 2;
			break;
		}

		Sleep(1000);
	}
}

/*
	다음 break point 지점까지 Run 하는 함수
*/
void step_run(DWORD break_point_address, PCONTEXT current_context)
{
	current_context->EFlags ^= 0x100;
	current_context->Dr0 = break_point_address;
	current_context->Dr1 = 0;
	current_context->Dr2 = 0;
	current_context->Dr6 = 0;
	current_context->Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
	current_context->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
}


/*
	잘못 눌러 call 명령어를 step into로 진입하였을 때
	뒤로 돌아가기를 지원하는 함수이다.
*/
void step_rewind(MOD_CONTEXT* rewind_context, PCONTEXT current_context)
{
	
	current_context->ContextFlags |= CONTEXT_DEBUG_REGISTERS;

	current_context->Dr0 = rewind_context->Dr0;
	current_context->Dr1 = rewind_context->Dr1;
	current_context->Dr2 = rewind_context->Dr2;
	current_context->Dr3 = rewind_context->Dr3;
	current_context->Dr6 = rewind_context->Dr6;
	current_context->Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);

	current_context->FloatSave = rewind_context->FloatSave;

	current_context->SegGs = rewind_context->SegGs;
	current_context->SegFs = rewind_context->SegFs;
	current_context->SegEs = rewind_context->SegEs;
	current_context->SegDs = rewind_context->SegDs;

	current_context->Edi = rewind_context->Edi;
	current_context->Esi = rewind_context->Esi;
	current_context->Ebx = rewind_context->Ebx;
	current_context->Edx = rewind_context->Edx;
	current_context->Ecx = rewind_context->Ecx;
	current_context->Eax = rewind_context->Eax;

	current_context->Ebp = rewind_context->Ebp;
	current_context->Eip = rewind_context->Eip;
	current_context->SegCs = rewind_context->SegCs;
	current_context->EFlags ^= 0x100;
	current_context->Esp = rewind_context->Esp;
	current_context->SegSs = rewind_context->SegSs;
}

/*
	call 명령어 안으로 들어가지 않고 바로 다음줄 명령어까지 실행하는 
	step over 기능을 수행하는 함수
*/
void step_over(PCONTEXT current_context, DWORD next_line_address)
{
	if (next_line_address != 0)
	{
		current_context->EFlags ^= 0x100;
		current_context->Dr0 = next_line_address;
		current_context->Dr1 = 0;
		current_context->Dr2 = 0;
		current_context->Dr3 = 0;
		current_context->Dr6 = 0;
		current_context->Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
		current_context->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
	}
}

/*
	VEH Debugger로 실행되서는 안되는 함수의 주소를 획득합니다.

	매개변수로 전달된 except_function_array(DWORD 배열 - 디버깅하지않고 넘어갈 함수 주소 리스트)에 
	GetProcAddress 함수로 획득한 함수 주소를 넣은 후 획득한 함수 주소 개수를 반환하는 함수
*/
UINT get_veh_except_function_address(DWORD* except_function_array)
{
	FARPROC except_function = NULL;
	UINT except_function_count = 0;

	except_function = (FARPROC)GetProcAddress(GetModuleHandleA(EXCEPT_RTL_ENTER_CRITICAL_SECTION_DLL), EXCEPT_RTL_ENTER_CRITICAL_SECTION);
	if (except_function != NULL)
	{
		except_function_array[except_function_count] = (DWORD)except_function;
		except_function_count++;
	}

	return except_function_count;
}

BOOL heap_pooling(LPVOID pooling_address)
{
	PDWORD temp_pool = NULL;
	int copy_cnt = 0;

	if (allocate_tracker == NULL)
	{
		allocate_tracker = (PDWORD)malloc(sizeof(PDWORD));
		if (allocate_tracker == NULL)
		{
			return FALSE;
		}

		if (pooling_address == NULL)
		{
			return FALSE;
		}

		allocate_tracker[0] = pooling_address;
		heap_size++;
	}

	else
	{
		PDWORD temp_pool = NULL;
		UINT copy_cnt = 0;

		temp_pool = (PDWORD)malloc(sizeof(PDWORD) * (heap_size + 1));

		for (copy_cnt = 0; copy_cnt < heap_size; copy_cnt++)
		{
			temp_pool[copy_cnt] = allocate_tracker[copy_cnt];
		}

		temp_pool[copy_cnt] = pooling_address;

		free(allocate_tracker);
		allocate_tracker = NULL;

		allocate_tracker = (PDWORD)malloc(sizeof(PDWORD) * (heap_size + 1));
		if (allocate_tracker == NULL)
		{
			return FALSE;
		}

		for (copy_cnt = 0; copy_cnt <= heap_size; copy_cnt++)
		{
			allocate_tracker[copy_cnt] = temp_pool[copy_cnt];
			printf("allocate_tracker[%d] : %08X <=> temp_pool[%d] : %08X\n", copy_cnt, allocate_tracker[copy_cnt], copy_cnt, temp_pool[copy_cnt]);
		}

		free(temp_pool);
		heap_size++;
	}

	return TRUE;
}

BOOL finalize()
{
	UINT free_cnt = 0;

	for (free_cnt = 0; free_cnt < heap_size; free_cnt++)
	{
		free(allocate_tracker[free_cnt]);
		allocate_tracker[free_cnt] = NULL;
	}

	free(allocate_tracker);

	return TRUE;
}

BOOL write_log(char* log_text)
{
	DWORD write_size = 0;

	if ((log_file_handle == INVALID_HANDLE_VALUE) || (log_file_handle == NULL))
	{
		MessageBoxA(NULL, "log file handle is invalid", " ", MB_OK);
		return FALSE;
	}

	if (!WriteFile(log_file_handle, log_text, strlen(log_text), &write_size, NULL))
	{
		MessageBoxA(NULL, "log write fail", " ", MB_OK);
		return FALSE;
	}

	return TRUE;
}