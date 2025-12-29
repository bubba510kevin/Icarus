#include "NamedPipeLuna.h"
#include <Windows.h>

static HANDLE hPipe = INVALID_HANDLE_VALUE;

extern "C" {

BOOL __stdcall StartPipeServer(const wchar_t* pipeName)
{
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        4096,
        4096,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    return connected;
}

BOOL __stdcall PipeSend(const char* msg, DWORD size)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD written = 0;
    return WriteFile(hPipe, msg, size, &written, NULL);
}

DWORD __stdcall PipeReceive(char* buffer, DWORD bufferSize)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return 0;

    DWORD read = 0;
    BOOL ok = ReadFile(hPipe, buffer, bufferSize, &read, NULL);
    return ok ? read : 0;
}

void __stdcall ClosePipe()
{
    if (hPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
}

}
