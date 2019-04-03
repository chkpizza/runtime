/*
	veh redirect & veh debugging test program
*/

#include <stdio.h>
#include <Windows.h>

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

	//AddVectoredExceptionHandler(1, FirstHandler);
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
}

LONG WINAPI FirstHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	printf("FirstHandler call!\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

LONG WINAPI SecondHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	printf("SecondHandler call!\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}