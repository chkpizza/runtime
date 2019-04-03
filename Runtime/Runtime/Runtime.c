#include "disassemble.h"
#include "memory_scanner.h"
#include "dr_debugger.h"


int main() 
{
	read_target_process_memory();
	system("pause");
	set_thread_context();
	printf("end!\n");

	return 0;
}