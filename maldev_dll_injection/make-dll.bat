@ECHO OFF

cl.exe /O2 /D_USRDLL /D_WINDLL shellcode-dll.cpp shellcode-dll.def /MT /link /DLL /OUT:shellcode-dll.dll