# Shellcode DLL and Injector

This project demonstrates the creation of a DLL (Dynamic Link Library) using C++ and provides an injector program to inject the DLL into a running process on Windows.

## Files

### 1. `shellcode-dll.cpp`

This file contains the source code for the DLL. It includes the shellcode that will be executed when the DLL is loaded into a process. Modify the shellcode as needed for your specific use case.

### 2. `shellcode.def`

The definition file (`shellcode.def`) is used to export functions from the DLL. Ensure that it includes the necessary exports for your DLL. Modify it if additional exports are needed.

### 3. `make-dll.bat`

This batch file (`make-dll.bat`) compiles the DLL using the Microsoft Visual C++ compiler (`cl`). It uses the definition file (`shellcode.def`) during compilation to specify the exports. Run this batch file to compile the DLL.

```bash
make-dll.bat
```
### 4. `shellcode-dll-injector.cpp`

This file contains the source code for an injector program. It loads the DLL into a target process using the LoadLibrary function and injects it using various injection techniques.


## Compilation and Usage

### 1. Open a command prompt and navigate to the project directory.

### 2. Run the make-dll.bat batch file to compile the DLL.

```bash
make-dll.bat
```

### 3. After successful compilation, the DLL (shellcode-dll.dll) will be generated.

### 4. Compile the injector program (shellcode-dll-injector.cpp) using your preferred compiler.

```bash
cl shellcode-dll-injector.cpp
```

### 5. Run the injector program, specifying the target process ID and the DLL to inject.

```bash
shellcode-dll-injector.exe <target_process_id> shellcode-dll.dll
```

## Additional Notes

- Ensure that you have the necessary permissions to inject code into the target process.

- Customize the shellcode and DLL exports based on your requirements.

## Official Documentation

For more details on DLLs and process injection on Windows, refer to the official Microsoft documentation:

- [Dynamic-Link Libraries (DLLs)](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-libraries)

- [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)