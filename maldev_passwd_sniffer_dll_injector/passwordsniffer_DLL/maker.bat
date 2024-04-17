@ECHO OFF

cl.exe /nologo /W0 passwordVeraCryptSniffer.cpp /MT /link /DLL detours\lib.X64\detours.lib /OUT:passwordVeraCryptSniffer.dll

del *.obj *.lib *.exp