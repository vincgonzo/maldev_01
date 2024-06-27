# Trojan inject Shellcode DLL in VeraCrypt Software

This project demonstrates the creation of a DLL (Dynamic Link Library) using C++ and provides an injector program to inject the DLL into a running process on Windows.
you can find a demo video on Youtube there : https://youtu.be/HnqvlEFgqfE

## Files

### 1. `passwordVeraCryptSniffer.cpp`

This file contains the source code for the DLL. You'll have to modify the destination of the file or implement a exfiltration mechanism if needed

### 2. `DLLinjectorTrojan.cpp`

This is the Trojan part of the exploit. You'll have to insert hexa version of the previous dll when compiled (mangling it is adviced).
When launch the program unpack the dll / save it in the TMP directory of current user and attached the dll to Veracrypt software.

## Additional Notes

- All code in this repo is for educational purposes only.

- The exploit working in the 1.24 version of VeraCrypt software.

- Customize the shellcode and DLL exports based on your requirements.
