#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>

void start();
BOOL insert_veh_win10();
BOOL insert_veh_win7();
LONG WINAPI first_veh(
	struct _EXCEPTION_POINTERS* ExceptionInfo
);

char tmp_buffer[512];

int step_count = 0;

BOOL __stdcall DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	HANDLE start_func = NULL;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hInstDLL);

		start_func = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start, NULL, 0, NULL);
		CloseHandle(start_func);
	}
	return TRUE;
}

void start()
{
	int i = 0;
	MessageBoxA(NULL, "inject success", " ", MB_OK);
	insert_veh_win7();
	while (1)
	{
		i++;
		Sleep(1000);
	}
}

LONG WINAPI first_veh(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		memset(tmp_buffer, 0, 512);
		step_count++;

		sprintf(tmp_buffer, "exception addr : %08X\neip : %08X\nexception code : %08X\n ESP : %08X EBP : %08X ECX : %08X EDX : %08X EDI : %08X ESI : %08X\n",
			ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Eip,
			ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx, 
			ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Esi);

		ExceptionInfo->ContextRecord->EFlags |= 0x100;
		ExceptionInfo->ContextRecord->Dr0 = 0;
		ExceptionInfo->ContextRecord->Dr6 = 0;
		ExceptionInfo->ContextRecord->Dr7 = 0;
		ExceptionInfo->ContextRecord->ContextFlags |= CONTEXT_DEBUG_REGISTERS;

		if (MessageBoxA(NULL, tmp_buffer, "escape", MB_OKCANCEL) == IDCANCEL)
		{
			ExceptionInfo->ContextRecord->EFlags ^= 0x100;
			MessageBoxA(NULL, "escape single step", " escape", MB_OK);
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
		return EXCEPTION_CONTINUE_SEARCH;
	
}

BOOL insert_veh_win10()
{
	DWORD ldr;
	HMODULE ntdll;
	FARPROC allocate_heap;
	FARPROC add_veh;
	FARPROC encode_pointer;
	FARPROC srw_lock;
	DWORD* allocate;
	DWORD insert_func = (DWORD)first_veh;
	byte inner_add_veh[100] = { 0, };
	byte handler_list[100] = { 0, };
	int i = 0;
	DWORD calc_call = 0;
	DWORD convert_handler_list = 0;
	DWORD tmp_convert_var = 0;
	DWORD handler_offset = 0;
	DWORD handler_offset2 = 0;
	DWORD LdrProtectMrData = 0;
	DWORD first_handler_buffer, second_handler_buffer;
	DWORD encode_my_handler;

	__asm {
		push eax
		push ecx
		mov eax, fs:[0x30]
		mov ecx, ds : [eax + 0x18]
		mov ldr, ecx
		pop ecx
		pop eax
	}

	ntdll = LoadLibraryA("ntdll.dll");
	allocate_heap = GetProcAddress(ntdll, "RtlAllocateHeap");
	add_veh = GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");
	encode_pointer = GetProcAddress(ntdll, "RtlEncodePointer");
	srw_lock = GetProcAddress(ntdll, "RtlAcquireSRWLockExclusive");

	memcpy(inner_add_veh, (byte*)add_veh + 14, 20);

	calc_call = (DWORD32)add_veh + 0x0D + (DWORD32)inner_add_veh[0] + 5;

	memcpy(handler_list, (byte*)calc_call + 0x77, 4);

	tmp_convert_var = (DWORD)handler_list[3];
	tmp_convert_var = tmp_convert_var << 24;
	convert_handler_list = tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[2];
	tmp_convert_var = tmp_convert_var << 16;
	convert_handler_list = convert_handler_list + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[1];
	tmp_convert_var = tmp_convert_var << 8;
	convert_handler_list = convert_handler_list + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[0];
	convert_handler_list = convert_handler_list + tmp_convert_var;

	memset(inner_add_veh, 0, sizeof(inner_add_veh));
	memcpy(inner_add_veh, (byte*)calc_call + 0x7f, 4);

	tmp_convert_var = 0;
	tmp_convert_var = (DWORD)inner_add_veh[3];
	tmp_convert_var = tmp_convert_var << 24;
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[2];
	tmp_convert_var = tmp_convert_var << 16;
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[1];
	tmp_convert_var = tmp_convert_var << 8;
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[0];
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	LdrProtectMrData = LdrProtectMrData + calc_call + 0x7e + 5;

	allocate = (DWORD*)allocate_heap(ldr, 0, 0x10);
	memset(allocate, 0, 0x10);
	encode_my_handler = encode_pointer(insert_func);

	__asm {
		push 0
		call LdrProtectMrData	
		push ebx
		mov ebx, convert_handler_list
		push[ebx]
		call srw_lock
		push edi
		mov edi, [ebx]
		mov dword ptr[edi], 0
		pop edi
		pop ebx
	}


	__asm {
		push edi
		push ebx;
		mov ebx, convert_handler_list
			lea edi, [ebx + 4]
			mov handler_offset, edi
			pop ebx;
		pop edi;
	}

	__asm {
		push edi
		push eax
		mov edi, handler_offset
		mov eax, [edi]
		mov handler_offset2, eax
		pop eax
		pop edi
	}

	__asm {
		push edx
		push ecx
		push edi
		mov ecx, convert_handler_list
		mov edx, [ecx + 4]
		mov first_handler_buffer, edx
		mov edx, [ecx + 8]
		mov second_handler_buffer, edx
		pop edi
		pop ecx
		pop edx
	}

	if (first_handler_buffer == (convert_handler_list + 4) && second_handler_buffer == (convert_handler_list + 4))
	{
		AddVectoredExceptionHandler(1, first_veh);
		return TRUE;
	}

	//내 핸들러 heap 설정
	__asm {
		push edx
		push ecx
		push edi
		mov edx, first_handler_buffer
		mov ecx, allocate
		mov edi, convert_handler_list
		mov[ecx], edx					//FirstHandler
		add edi, 4
		mov[ecx + 4], edi				//_LdrpVectorHandlerList + 4
		mov dword ptr[ecx + 8], 1		//1
		mov edi, encode_my_handler
		mov[ecx + 0x0c], edi			//myhandler encode pointer
		pop edi
		pop ecx
		pop edx
	}
	
	__asm {
		push edx
		push ecx
		push edi
		push esi
		mov ecx, convert_handler_list
		mov edx, allocate
		mov[ecx + 4], edx
		mov edi, first_handler_buffer
		mov[edi + 4], edx
		pop esi
		pop edi
		pop ecx
		pop edx
	}

	return TRUE;
}

BOOL insert_veh_win7()
{
	DWORD ldr;
	HMODULE ntdll;
	FARPROC allocate_heap;
	FARPROC add_veh;
	FARPROC encode_pointer;
	FARPROC srw_lock;
	DWORD* allocate;
	DWORD insert_func = (DWORD)first_veh;
	DWORD inner_function_addr = 0;
	byte inner_add_veh[100] = { 0, };
	byte handler_list[100] = { 0, };
	int i = 0;
	DWORD calc_call = 0;
	DWORD convert_handler_list = 0;
	DWORD tmp_convert_var = 0;
	DWORD handler_offset = 0;
	DWORD handler_offset2 = 0;
	DWORD LdrProtectMrData = 0;
	DWORD first_handler_buffer, second_handler_buffer;
	DWORD encode_my_handler;

	__asm {
		push eax
		push ecx
		mov eax, fs:[0x30]
		mov ecx, ds : [eax + 0x18]
		mov ldr, ecx
		pop ecx
		pop eax
	}

	ntdll = LoadLibraryA("ntdll.dll");
	allocate_heap = GetProcAddress(ntdll, "RtlAllocateHeap");
	add_veh = GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");
	encode_pointer = GetProcAddress(ntdll, "RtlEncodePointer");
	srw_lock = GetProcAddress(ntdll, "RtlAcquireSRWLockExclusive");

	memcpy(inner_add_veh, (byte*)add_veh + 14, 20);

	tmp_convert_var = (DWORD)inner_add_veh[3];
	tmp_convert_var = tmp_convert_var << 24;
	inner_function_addr = tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[2];
	tmp_convert_var = tmp_convert_var << 16;
	inner_function_addr = inner_function_addr + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[1];
	tmp_convert_var = tmp_convert_var << 8;
	inner_function_addr = inner_function_addr + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[0];
	inner_function_addr = inner_function_addr + tmp_convert_var;

	calc_call = (DWORD32)add_veh + 0x0D + inner_function_addr + 5;
	memcpy(handler_list, (byte*)calc_call + 0x3A, 4);

	tmp_convert_var = (DWORD)handler_list[3];
	tmp_convert_var = tmp_convert_var << 24;
	convert_handler_list = tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[2];
	tmp_convert_var = tmp_convert_var << 16;
	convert_handler_list = convert_handler_list + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[1];
	tmp_convert_var = tmp_convert_var << 8;
	convert_handler_list = convert_handler_list + tmp_convert_var;

	tmp_convert_var = (DWORD)handler_list[0];
	convert_handler_list = convert_handler_list + tmp_convert_var;

	memset(inner_add_veh, 0, sizeof(inner_add_veh));
	memcpy(inner_add_veh, (byte*)calc_call + 0x7f, 4);


	tmp_convert_var = 0;
	tmp_convert_var = (DWORD)inner_add_veh[3];
	tmp_convert_var = tmp_convert_var << 24;
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[2];
	tmp_convert_var = tmp_convert_var << 16;
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[1];
	tmp_convert_var = tmp_convert_var << 8;
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	tmp_convert_var = (DWORD)inner_add_veh[0];
	LdrProtectMrData = LdrProtectMrData + tmp_convert_var;

	LdrProtectMrData = LdrProtectMrData + calc_call + 0x7e + 5;

	allocate = (DWORD*)allocate_heap(ldr, 0, 0x10);
	memset(allocate, 0, 0x10);
	encode_my_handler = encode_pointer(insert_func);

	__asm {
		push edi
		push ebx;
		mov ebx, convert_handler_list
		lea edi, [ebx + 4]
		mov handler_offset, edi
		pop ebx;
		pop edi;
	}

	__asm {
		push edi
		push eax
		mov edi, handler_offset
		mov eax, [edi]
		mov handler_offset2, eax
		pop eax
		pop edi
	}
	__asm {
		push edx
		push ecx
		push edi
		mov ecx, convert_handler_list
		mov edx, [ecx + 4]
		mov first_handler_buffer, edx
		mov edx, [ecx + 8]
		mov second_handler_buffer, edx
		pop edi
		pop ecx
		pop edx
	}

	if (first_handler_buffer == (convert_handler_list + 4) && second_handler_buffer == (convert_handler_list + 4))
	{
		AddVectoredExceptionHandler(1, first_veh);
		return TRUE;
	}

	__asm {
		push edx
		push ecx
		push edi
		mov edx, first_handler_buffer
		mov ecx, allocate
		mov edi, convert_handler_list
		mov[ecx], edx					
		add edi, 4
		mov[ecx + 4], edi				
		mov dword ptr[ecx + 8], 1		
		mov edi, encode_my_handler
		mov[ecx + 0x0c], edi				
		pop edi
		pop ecx
		pop edx
	}

	__asm {
		push edx
		push ecx
		push edi
		push esi
		mov ecx, convert_handler_list
		mov edx, allocate
		mov[ecx + 4], edx
		mov edi, first_handler_buffer
		mov[edi + 4], edx
		pop esi
		pop edi
		pop ecx
		pop edx
	}


	return TRUE;
}