#include <Windows.h>
#include "Frame.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {

#ifdef _DEBUG
	return TRUE;
#endif

	switch (ul_reason_for_call) {

		case DLL_PROCESS_ATTACH: {

			DisableThreadLibraryCalls(hModule);

			Bootstrap();

			break;
		}
	}

	return TRUE;
}

