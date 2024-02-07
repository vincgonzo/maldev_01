@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcprocess_enumerator.cpp /link /OUT:process_enumerator.exe /SUBSYSTEM:CONSOLE /MACHINE:x64