@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcmapview.cpp /link /OUT:mapview.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj