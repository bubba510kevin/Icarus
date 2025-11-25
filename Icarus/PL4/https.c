#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include <stdbool.h>
#include <sys/stat.h>

__declspec(dllexport) char *Ares(){

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Path to your executable
    const char* exePath = "";

    // Start the process
    CreateProcessA(
        "cmd.exe",   // Application name
        exePath,      // Command line arguments
        NULL,      // Process handle not inheritable
        NULL,      // Thread handle not inheritable
        FALSE,     // Set handle inheritance to FALSE
        0,         // No creation flags
        NULL,      // Use parent's environment block
        NULL,      // Use parent's starting directory 
        &si,       // Pointer to STARTUPINFO structure
        &pi
    );       // Pointer to PROCESS_INFORMATION structure
    

    // Wait until the process exits
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

}