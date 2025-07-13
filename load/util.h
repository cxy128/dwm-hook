#pragma once

#include <Windows.h>
#include <string>

constexpr auto PAGE_SIZE = 0x1000;

constexpr auto STATUS_SUCCESS = 0;

#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

enum class SystemInformationClass :unsigned __int32 {

	SystemProcessInformation = 0x5,
	SystemModuleInformation = 0xb,
	SystemPerformanceTraceInformation = 0x1f,
	SystemSupportedProcessArchitectures = 0xb5
};

enum class ProcessInformationClass :unsigned __int32 {

	ProcessBasicInformation = 0,
};

struct UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
};

struct CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

typedef LONG KPRIORITY;

enum KWAIT_REASON {

};

struct SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION {

	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
	ULONG_PTR PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
};

typedef BOOL(*fnDllMain)(void* hModule, unsigned __int32 ul_reason_for_call, void* lpReserved);

using fnZwAllocateVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

using fnZwFreeVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

using fnZwReadVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

using fnZwWriteVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

using fnZwProtectVirtualMemory = NTSTATUS(*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

using fnZwGetNextThread = NTSTATUS(*)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);

using fnZwQueueApcThreadEx = NTSTATUS(*)(HANDLE ThreadHandle, ULONG Env, void* ApcRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

using fnZwQuerySystemInformation = NTSTATUS(*)(SystemInformationClass InformationClass, PVOID SystemInfoBuffer, ULONG SystemInfoBufferSize, PULONG BytesReturned);

using fnZwQueryInformationProcess = NTSTATUS(*)(HANDLE ProcessHandle, ProcessInformationClass InformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

inline fnZwAllocateVirtualMemory ZwAllocateVirtualMemory = nullptr;

inline fnZwFreeVirtualMemory ZwFreeVirtualMemory = nullptr;

inline fnZwReadVirtualMemory ZwReadVirtualMemory = nullptr;

inline fnZwWriteVirtualMemory ZwWriteVirtualMemory = nullptr;

inline fnZwProtectVirtualMemory ZwProtectVirtualMemory = nullptr;

inline fnZwGetNextThread ZwGetNextThread = nullptr;

inline fnZwQueueApcThreadEx ZwQueueApcThreadEx = nullptr;

inline fnZwQuerySystemInformation ZwQuerySystemInformation = nullptr;

inline fnZwQueryInformationProcess ZwQueryInformationProcess = nullptr;

bool InitSystemRoutineAddress();

DWORD GetProcessIdByName(std::wstring ProcessName);
