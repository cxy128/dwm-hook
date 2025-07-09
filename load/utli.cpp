#include <string>
#include "utli.h"

bool InitSystemRoutineAddress() {

	auto Handle = GetModuleHandleA("ntdll.dll");
	if (!Handle) {
		return false;
	}

	ZwAllocateVirtualMemory = (fnZwAllocateVirtualMemory)GetProcAddress(Handle, "ZwAllocateVirtualMemory");
	if (!ZwAllocateVirtualMemory) {
		return false;
	}

	ZwFreeVirtualMemory = (fnZwFreeVirtualMemory)GetProcAddress(Handle, "ZwFreeVirtualMemory");
	if (!ZwFreeVirtualMemory) {
		return false;
	}

	ZwReadVirtualMemory = (fnZwReadVirtualMemory)GetProcAddress(Handle, "ZwReadVirtualMemory");
	if (!ZwReadVirtualMemory) {
		return false;
	}

	ZwWriteVirtualMemory = (fnZwWriteVirtualMemory)GetProcAddress(Handle, "ZwWriteVirtualMemory");
	if (!ZwWriteVirtualMemory) {
		return false;
	}

	ZwProtectVirtualMemory = (fnZwProtectVirtualMemory)GetProcAddress(Handle, "ZwProtectVirtualMemory");
	if (!ZwProtectVirtualMemory) {
		return false;
	}

	ZwGetNextThread = (fnZwGetNextThread)GetProcAddress(Handle, "ZwGetNextThread");
	if (!ZwGetNextThread) {
		return false;
	}

	ZwQueueApcThreadEx = (fnZwQueueApcThreadEx)GetProcAddress(Handle, "ZwQueueApcThreadEx");
	if (!ZwQueueApcThreadEx) {
		return false;
	}

	ZwQuerySystemInformation = (fnZwQuerySystemInformation)GetProcAddress(Handle, "ZwQuerySystemInformation");
	if (!ZwQuerySystemInformation) {
		return false;
	}

	ZwQueryInformationProcess = (fnZwQueryInformationProcess)GetProcAddress(Handle, "ZwQueryInformationProcess");
	if (!ZwQueryInformationProcess) {
		return false;
	}

	return true;
}

DWORD GetProcessIdByName(std::wstring ProcessName) {

	auto ReturnLength = 0ul;
	auto Status = ZwQuerySystemInformation(SystemInformationClass::SystemProcessInformation, nullptr, 0, &ReturnLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {

		SYSTEM_PROCESS_INFORMATION* ProcessInformation = nullptr;
		auto RegionSize = ReturnLength + 0ull;
		Status = ZwAllocateVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
		if (NT_ERROR(Status)) {
			return 0;
		}

		Status = ZwQuerySystemInformation(SystemInformationClass::SystemProcessInformation, ProcessInformation, ReturnLength, &ReturnLength);
		if (NT_ERROR(Status)) {
			ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), nullptr, MEM_RELEASE);
			return 0;
		}

		for (; ProcessInformation->NextEntryOffset; ProcessInformation = (SYSTEM_PROCESS_INFORMATION*)((unsigned __int64)ProcessInformation + ProcessInformation->NextEntryOffset)) {

			if (!ProcessInformation->ImageName.Length) {
				continue;
			}

			if (!std::wstring(ProcessInformation->ImageName.Buffer).compare(ProcessName)) {

				ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), nullptr, MEM_RELEASE);

				return HandleToULong(ProcessInformation->ProcessId);
			}
		}

		ZwFreeVirtualMemory(GetCurrentProcess(), reinterpret_cast<void**>(&ProcessInformation), nullptr, MEM_RELEASE);
	}

	return 0;
}