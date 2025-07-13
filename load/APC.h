#pragma once

#include <Windows.h>
#include "util.h"

typedef void* (*fnLoadLibraryA)(const char* lpLibFileName);
typedef unsigned __int64 (*fnGetProcAddress)(void* hModule, const char* lpProcName);
typedef BOOLEAN(*fnRtlAddFunctionTable)(IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable, unsigned __int32 EntryCount, unsigned __int64 BaseAddress);

using fnVirtualAlloc = LPVOID(*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
using fnGetThreadContext = BOOL(*)(HANDLE hThread, LPCONTEXT lpContext);
using fnSetThreadContext = BOOL(*)(HANDLE hThread, CONTEXT* lpContext);
using fnRtlCopyMemory = void(*)(void* Destination, void* Source, unsigned __int64 Length);

struct MappingParameter {

	unsigned __int64 ImageBase;

	fnLoadLibraryA fLoadLibraryA;
	fnGetProcAddress fGetProcAddress;
	fnRtlAddFunctionTable fRtlAddFunctionTable;

	fnVirtualAlloc fVirtualAlloc;
	fnRtlCopyMemory fRtlCopyMemory;
	fnGetThreadContext fGetThreadContext;
	fnSetThreadContext fSetThreadContext;

	volatile bool IsExecution;
	volatile bool IsStartDllMain;
};

bool MappingModule(HANDLE ProcessHandle, unsigned __int64 ImageBase, void* __entry_point, unsigned __int64* __call_entry_point, unsigned __int64* ParameterAddress);

bool InsertAPC(HANDLE ProcessHandle, unsigned __int64 EntryPointAddress, unsigned __int64 ParameterAddress);

bool InitMappingParameter(MappingParameter* Parameter, void* ImageBase);

void UserApcRoutine(PVOID* NormalContext, unsigned __int64 EntryPoint, unsigned __int64 Parameter);
