@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcshellcode_runner.cpp /link /OUT:shellcode_runner.exe /SUBSYSTEM:CONSOLE /MACHINE:x64