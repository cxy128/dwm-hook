#pragma once

#include <Windows.h>
#include <string>

unsigned __int64 SearchSignature(unsigned __int64 ModuleAddress, unsigned char* SignatureBytes, const char* Segment, const char* Mask);

unsigned __int64 GetDestroyInstructionLength(unsigned __int64 PatchAddress);

bool PatchAddress(unsigned __int64 OriginAddress, void* Trampoline, void* Handler, std::string& OriginBytes, unsigned __int64 PatchSize);

bool RestoreAddress(unsigned __int64 OriginAddress, std::string OriginBytes, unsigned __int64 PatchSize);

bool IsHook(unsigned __int64 Address);