#pragma once
#include <Windows.h>

extern "C" {

__declspec(dllexport) BOOL __stdcall StartPipeServer(const wchar_t* pipeName);
__declspec(dllexport) BOOL __stdcall PipeSend(const char* msg, DWORD size);
__declspec(dllexport) DWORD __stdcall PipeReceive(char* buffer, DWORD bufferSize);
__declspec(dllexport) void __stdcall ClosePipe();

}


