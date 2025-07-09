#include "APC.h"

bool MappingModule(HANDLE ProcessHandle, unsigned __int64 ImageBase, void* __entry_point, unsigned __int64* __call_entry_point, unsigned __int64* ParameterAddress) {

	NTSTATUS Status = STATUS_SUCCESS;
	IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
	if (!DosHeader || DosHeader->e_magic != 0x5a4d) {
		return false;
	}

	IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(ImageBase + DosHeader->e_lfanew);
	IMAGE_FILE_HEADER* FileHeader = &NtHeader->FileHeader;
	IMAGE_OPTIONAL_HEADER* OptionalHeader = &NtHeader->OptionalHeader;

	unsigned __int64 ReturnSize = 0;

	unsigned char* ModuleAddress = nullptr;
	unsigned __int64 ModuleSize = OptionalHeader->SizeOfImage;

	unsigned char* ParameterAddressBuffer = nullptr;
	unsigned __int64 ParameterSize = PAGE_SIZE;

	unsigned char* EntryPointBuffer = nullptr;
	unsigned __int64 EntryPointSize = PAGE_SIZE;

	for (;;) {

		Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ModuleAddress), 0, &ModuleSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwWriteVirtualMemory(ProcessHandle, ModuleAddress, reinterpret_cast<void*>(ImageBase), PAGE_SIZE, &ReturnSize);
		if (NT_ERROR(Status)) {
			break;
		}

		MappingParameter Parameter = {};
		if (!InitMappingParameter(&Parameter, ModuleAddress)) {
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		IMAGE_SECTION_HEADER* Sections = IMAGE_FIRST_SECTION(NtHeader);

		for (int i = 0; i < FileHeader->NumberOfSections; i++, Sections++) {

			if (Sections->SizeOfRawData) {

				Status = ZwWriteVirtualMemory(
					ProcessHandle,
					reinterpret_cast<void*>(ModuleAddress + Sections->VirtualAddress),
					reinterpret_cast<void*>(ImageBase + Sections->PointerToRawData),
					Sections->SizeOfRawData,
					&ReturnSize);

				if (NT_ERROR(Status)) {
					break;
				}
			}
		}

		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ParameterAddressBuffer), 0, &ParameterSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwWriteVirtualMemory(ProcessHandle, ParameterAddressBuffer, &Parameter, sizeof(MappingParameter), &ReturnSize);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&EntryPointBuffer), 0, &EntryPointSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status)) {
			break;
		}

		Status = ZwWriteVirtualMemory(ProcessHandle, EntryPointBuffer, __entry_point, EntryPointSize, &ReturnSize);
		if (NT_ERROR(Status)) {
			break;
		}

		break;
	}

	if (NT_ERROR(Status)) {

		if (EntryPointBuffer) {
			ZwFreeVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&EntryPointBuffer), &EntryPointSize, MEM_DECOMMIT);
		}

		if (ParameterAddressBuffer) {
			ZwFreeVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ParameterAddressBuffer), &ParameterSize, MEM_DECOMMIT);
		}

		if (ModuleAddress) {
			ZwFreeVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&ModuleAddress), &ModuleSize, MEM_DECOMMIT);
		}

		return false;
	}

	*__call_entry_point = reinterpret_cast<unsigned __int64>(EntryPointBuffer);

	*ParameterAddress = reinterpret_cast<unsigned __int64>(ParameterAddressBuffer);

	return true;
}

bool InsertAPC(HANDLE ProcessHandle, unsigned __int64 EntryPointAddress, unsigned __int64 ParameterAddress) {

	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE ThreadHandle = nullptr;

	Status = ZwGetNextThread(ProcessHandle, nullptr, THREAD_ALL_ACCESS, 0, 0, &ThreadHandle);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned char* Rip = nullptr;
	unsigned __int64 RipSize = PAGE_SIZE;

	Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&Rip), 0, &RipSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned __int64 ReturnSize = 0;
	Status = ZwWriteVirtualMemory(ProcessHandle, Rip, UserApcRoutine, PAGE_SIZE, &ReturnSize);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned char* RipShellcode = nullptr;
	unsigned __int64 RipShellcodeSize = PAGE_SIZE;

	unsigned char Shellcode[] = {

		0x50,										// push rax
		0x51,										// push rcx
		0x52,										// push rdx
		0x53,										// push rbx
		//0x54,										// push rsp
		0x55,										// push rbp
		0x56,										// push rsi
		0x57,										// push rdi 
		0x41, 0x50,									// push r8
		0x41, 0x51,									// push r9
		0x41, 0x52,									// push r10
		0x41, 0x53,									// push r11
		0x41, 0x54,									// push r12
		0x41, 0x55,									// push r13
		0x41, 0x56,									// push r14
		0x41, 0x57,									// push r15

		0x48, 0x89, 0x25, 0x4f, 0x00, 0x00, 0x00,	// mov qword ptr ds:[0x00],rsp
		0x48, 0x83, 0xec, 0x38,						// sub rsp,38
		0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff,	// and rsp, FFFFFFFFFFFFFFF0

		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx,0x00
		0xff, 0x15, 0x2c, 0x00, 0x00, 0x00,			// call 0x00

		0x48, 0x8b, 0x25, 0x2d, 0x00, 0x00, 0x00,	// mov rsp,qword ptr [0x00]

		0x41, 0x5f,									// pop r15
		0x41, 0x5e,									// pop r14
		0x41, 0x5d,									// pop r13
		0x41, 0x5c,									// pop r12
		0x41, 0x5b,									// pop r11
		0x41, 0x5a,									// pop r10
		0x41, 0x59,									// pop r9
		0x41, 0x58,									// pop r8
		0x5f,										// pop rdi
		0x5e,										// pop rsi
		0x5d,										// pop rbp
		//0x5c,										// pop rsp
		0x5b,										// pop rbx
		0x5a,										// pop rdx
		0x59,										// pop rcx
		0x58,										// pop rax

		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,				// jmp 0x00
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// Trap->rip
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// call address
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// save rsp
	};

	Status = ZwAllocateVirtualMemory(ProcessHandle, reinterpret_cast<void**>(&RipShellcode), 0, &RipShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_ERROR(Status)) {
		return false;
	}

	Status = ZwWriteVirtualMemory(ProcessHandle, RipShellcode, Shellcode, sizeof(Shellcode), &ReturnSize);
	if (NT_ERROR(Status)) {
		return false;
	}

	Status = ZwQueueApcThreadEx(ThreadHandle, 1, Rip, reinterpret_cast<void*>(RipShellcode), reinterpret_cast<void*>(EntryPointAddress), reinterpret_cast<void*>(ParameterAddress));

	CloseHandle(ThreadHandle);

	return NT_SUCCESS(Status);
}

bool InitMappingParameter(MappingParameter* Parameter, void* ImageBase) {

	auto Kernel32 = GetModuleHandleW(L"Kernel32.dll");
	if (!Kernel32) {
		return false;
	}

	auto ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		return false;
	}

	Parameter->IsExecution = false;
	Parameter->IsStartDllMain = false;

	Parameter->ImageBase = reinterpret_cast<unsigned __int64>(ImageBase);

	Parameter->fLoadLibraryA = reinterpret_cast<fnLoadLibraryA>(GetProcAddress(Kernel32, "LoadLibraryA"));
	Parameter->fGetProcAddress = reinterpret_cast<fnGetProcAddress>(GetProcAddress(Kernel32, "GetProcAddress"));
	Parameter->fRtlAddFunctionTable = reinterpret_cast<fnRtlAddFunctionTable>(GetProcAddress(Kernel32, "RtlAddFunctionTable"));

	if (!Parameter->fLoadLibraryA || !Parameter->fGetProcAddress || !Parameter->fRtlAddFunctionTable) {
		return false;
	}

	Parameter->fVirtualAlloc = reinterpret_cast<fnVirtualAlloc>(GetProcAddress(Kernel32, "VirtualAlloc"));
	Parameter->fRtlCopyMemory = reinterpret_cast<fnRtlCopyMemory>(GetProcAddress(ntdll, "RtlCopyMemory"));
	Parameter->fGetThreadContext = reinterpret_cast<fnGetThreadContext>(GetProcAddress(Kernel32, "GetThreadContext"));
	Parameter->fSetThreadContext = reinterpret_cast<fnSetThreadContext>(GetProcAddress(Kernel32, "SetThreadContext"));

	if (!Parameter->fVirtualAlloc || !Parameter->fRtlCopyMemory || !Parameter->fGetThreadContext || !Parameter->fSetThreadContext) {
		return false;
	}

	return true;
}

void UserApcRoutine(PVOID* NormalContext, unsigned __int64 EntryPoint, unsigned __int64 Parameter) {

	unsigned __int8* Shellcode = reinterpret_cast<unsigned __int8*>(NormalContext);

	auto Mapping = reinterpret_cast<MappingParameter*>(Parameter);

	auto ThreadHandle = reinterpret_cast<HANDLE>(-2);

	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_ALL;
	if (!Mapping->fGetThreadContext(ThreadHandle, &ThreadContext)) {
		return;
	}

	unsigned __int64 ShellcodeSize = 0x1000;
	unsigned char* ShellcodeAddress = reinterpret_cast<unsigned __int8*>(Mapping->fVirtualAlloc(nullptr, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!ShellcodeAddress) {
		return;
	}

	Mapping->fRtlCopyMemory(ShellcodeAddress, Shellcode, ShellcodeSize);

	*(unsigned __int64*)&ShellcodeAddress[43] = Parameter;
	*(unsigned __int64*)&ShellcodeAddress[93] = ThreadContext.Rip;
	*(unsigned __int64*)&ShellcodeAddress[101] = EntryPoint;

	ThreadContext.Rip = (unsigned __int64)ShellcodeAddress;

	Mapping->fSetThreadContext(ThreadHandle, &ThreadContext);
}
