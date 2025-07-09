#include "util.h"
#include "Zydis/Zydis.h"

unsigned __int64 SearchSignature(unsigned __int64 ModuleAddress, unsigned char* SignatureBytes, const char* Segment, const char* Mask) {

	IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ModuleAddress);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(ModuleAddress + DosHeader->e_lfanew);

	unsigned __int64 MaskLength = strlen(Mask);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeader);

	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {

		IMAGE_SECTION_HEADER* Section = &Sections[i];

		if (_stricmp((const char*)(Section->Name), Segment) == 0) {

			unsigned __int64 SectionAddress = ModuleAddress + Section->VirtualAddress;

			for (unsigned __int32 n = 0; n < Section->Misc.VirtualSize - MaskLength; n++) {

				int f = 1;

				for (unsigned __int64 x = 0; x < MaskLength; x++) {

					if (((((unsigned char*)(SectionAddress + n))[x]) == SignatureBytes[x]) || Mask[x] == '?') {
						continue;
					}

					f = 0;
					break;
				}

				if (f) {
					return SectionAddress + n;
				}
			}
		}
	}

	return 0;
}

unsigned __int64 GetDestroyInstructionLength(unsigned __int64 PatchAddress) {

	unsigned __int64 Length = 0;

	ZydisDecoder decoder = {};
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	for (;;) {

		if (Length >= 14) {
			break;
		}

		ZydisDecodedInstruction instruction = {};

		auto Status = ZydisDecoderDecodeInstruction(&decoder, nullptr, reinterpret_cast<__int8*>(PatchAddress) + Length, 0x10, &instruction);

		if (ZYAN_FAILED(Status)) {

			return 0;
		}

		Length += instruction.length;
	}

	return Length;
}

bool PatchAddress(unsigned __int64 OriginAddress, void* Trampoline, void* Handler, std::string& OriginBytes, unsigned __int64 PatchSize) {

	if (IsHook(OriginAddress)) {
		return true;
	}

	unsigned char TrampolineBytes[] = {
	   0x6A, 0x00,													// push 0
	   0x36, 0xC7, 0x04, 0x24 ,0x00, 0x00, 0x00, 0x00,	 			// mov dword ptr ss : [rsp] , 0x00
	   0x36, 0xC7, 0x44, 0x24 ,0x04 ,0x00, 0x00, 0x00,  0x00,		// mov dword ptr ss : [rsp + 4] , 0x00
	   0xC3															// ret
	};

	unsigned char JmpBytes[] = {
	   0xff,0x25,0x00,0x00,0x00,0x00,
	   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	*(unsigned __int32*)&TrampolineBytes[6] = (unsigned __int32)((OriginAddress + PatchSize) & 0xFFFFFFFF);
	*(unsigned __int32*)&TrampolineBytes[15] = (unsigned __int32)(((OriginAddress + PatchSize) >> 32) & 0xFFFFFFFF);

	unsigned __int8* Address = reinterpret_cast<unsigned __int8*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!Address) {
		return false;
	}

	RtlZeroMemory(Address, 0x1000);

	RtlCopyMemory(Address, reinterpret_cast<unsigned __int64*>(OriginAddress), PatchSize);
	RtlCopyMemory(Address + PatchSize, TrampolineBytes, sizeof(TrampolineBytes));

	*reinterpret_cast<unsigned __int64*>(Trampoline) = reinterpret_cast<unsigned __int64>(Address);

	if (OriginBytes.empty()) {
		OriginBytes.assign(reinterpret_cast<const __int8*>(OriginAddress), PatchSize);
	}

	DWORD OldProtect = 0;
	if (!VirtualProtect(reinterpret_cast<void*>(OriginAddress), PatchSize, PAGE_EXECUTE_READWRITE, &OldProtect)) {
		return false;
	}

	*(unsigned __int64*)(&JmpBytes[6]) = (unsigned __int64)Handler;

	RtlCopyMemory((void*)OriginAddress, JmpBytes, sizeof(JmpBytes));

	if (!VirtualProtect(reinterpret_cast<void*>(OriginAddress), PatchSize, OldProtect, &OldProtect)) {
		return false;
	}

	return true;
}

bool RestoreAddress(unsigned __int64 OriginAddress, std::string OriginBytes, unsigned __int64 PatchSize) {

	if (!IsHook(OriginAddress)) {
		return true;
	}

	DWORD OldProtect = 0;
	if (!VirtualProtect(reinterpret_cast<void*>(OriginAddress), PatchSize, PAGE_EXECUTE_READWRITE, &OldProtect)) {
		return false;
	}

	RtlCopyMemory(reinterpret_cast<void*>(OriginAddress), OriginBytes.data(), PatchSize);

	if (!VirtualProtect(reinterpret_cast<void*>(OriginAddress), PatchSize, OldProtect, &OldProtect)) {
		return false;
	}

	return true;
}

bool IsHook(unsigned __int64 Address) {

	if (*reinterpret_cast<__int16*>(Address) == (__int16)0x25FF && *reinterpret_cast<__int32*>(Address + 2) == (__int32)0x00000000) {
		return true;
	}

	return false;
}