@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:passwordVeraCryptSniffer.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj