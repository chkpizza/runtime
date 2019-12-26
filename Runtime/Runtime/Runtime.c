#include "disassemble.h"
#include "memory_scanner.h"
#include "dr_debugger.h"

#pragma warning(disable:4996)

#define OBJECT_NAME "Local\\INTERPE"
#define PAGE_SIZE 0x1000

VOID init();
VOID sender();
VOID receiver();

//char* buf;
char* shared_memory;
HANDLE mapping_handle;


int main() 
{
	read_target_process_memory();
	system("pause");

	set_thread_context();
	printf("end!\n");
	
	/*
		#UI <==> Engine Library 통신 코드
	*/
	init();
	while (1)
	{
		receiver();
	}

	return 0;
}

VOID init()
{
	mapping_handle = CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		PAGE_SIZE,
		OBJECT_NAME
	);

	shared_memory = (char*)MapViewOfFile(
		mapping_handle,
		PAGE_READONLY,
		0,
		0,
		0
	);
}

VOID sender()
{
	char message[512];
	memset(message, 0, 512);
	printf(">> ");
	scanf("%s", message);

	strcpy(shared_memory, message);
}

VOID receiver()
{
	while (1)
	{
		if (strstr(shared_memory, "exception"))
		{
			MessageBoxA(NULL, shared_memory, "engine", MB_OK);
			sender();
			break;
		}

		Sleep(1000);
	}
}