#pragma once
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

DWORD global_please;

void set_thread_context();

uint32_t get_pid();
