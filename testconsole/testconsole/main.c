/*
	veh redirect & veh debugging test program
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>

int step_count = 0;

LONG WINAPI FirstHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
);


LONG WINAPI SecondHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
);

void test_func();

int main()
{
	DWORD test_func_addr = 0;
	test_func_addr = (DWORD)test_func;
	printf("test_func_addr : %08X\n", test_func);

	AddVectoredExceptionHandler(10, SecondHandler);
	AddVectoredExceptionHandler(1, FirstHandler);
	system("pause");

	while (1)
	{
		test_func();
		Sleep(2000);
	}
	return 0;
}

void test_func()
{
	printf("test_func call!\n");
	//system("pause");
	//MessageBoxW(NULL, L"LCK Fuck up", L" ", MB_OK);
}

LONG WINAPI FirstHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	
	char tmp_buffer[512];
	printf("FirstHandler call\n");
	/*
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
	*/

}

LONG WINAPI SecondHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	printf("SecondHandler call!\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}