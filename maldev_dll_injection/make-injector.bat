@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcinjector-dll.cpp /link /OUT:injector-dll.exe /SUBSYSTEM:CONSOLE /MACHINE:x64