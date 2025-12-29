#include <windows.h>
#include <winhttp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#include "convenince.h"

#define BLOCK_SIZE (4*1024*1024) // 4 MB

// ---------------- Shared key ----------------
static const unsigned char SHARED_KEY[32] = {
    0x10,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
    0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89
};

// ---------------- AES encrypt/decrypt ----------------
unsigned char* pipen(const unsigned char* plaintext, int plaintext_len,
                     const unsigned char* key, unsigned char* iv, int* out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx); return NULL;
    }

    unsigned char* ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!ciphertext) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        free(ciphertext); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        free(ciphertext); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    *out_len = ciphertext_len;
    return ciphertext;
}

unsigned char* sam(const unsigned char* ciphertext, int ciphertext_len,
                   const unsigned char* key, const unsigned char* iv, int* out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx); return NULL;
    }

    unsigned char* plaintext = malloc(ciphertext_len + AES_BLOCK_SIZE);
    if (!plaintext) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    *out_len = plaintext_len; // return actual decrypted length
    return plaintext;
}

// ---------------- POST function ----------------
char* miku(https_t* prt) {
    if (!prt) return NULL;

    HINTERNET s = WinHttpOpen(L"Icarus", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return NULL;

    wchar_t wserver[256], wpath[512];
    MultiByteToWideChar(CP_ACP, 0, prt->server, -1, wserver, 256);
    MultiByteToWideChar(CP_ACP, 0, prt->fileserver, -1, wpath, 512);

    HINTERNET c = WinHttpConnect(s, wserver, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!c) { WinHttpCloseHandle(s); return NULL; }

    HINTERNET r = WinHttpOpenRequest(c, L"POST", wpath, NULL,
                                     WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!r) { WinHttpCloseHandle(c); WinHttpCloseHandle(s); return NULL; }

    BOOL ok = FALSE;

    if (prt->file_switch && prt->postfile) {
        HANDLE hFile = CreateFileA(prt->postfile, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

        unsigned char iv[16]; RAND_bytes(iv, 16);
        unsigned char prev_iv[16]; memcpy(prev_iv, iv, 16);

        DWORD file_size = GetFileSize(hFile, NULL);

        // send request with total content length including IV
        ok = WinHttpSendRequest(r, L"Content-Type: application/octet-stream\r\n",
                                -1, NULL, 0, file_size + 16, 0);
        if (!ok) { CloseHandle(hFile); goto cleanup; }

        DWORD written;
        WinHttpWriteData(r, iv, 16, &written);

        unsigned char buffer[BLOCK_SIZE];
        DWORD read;

        while (ReadFile(hFile, buffer, BLOCK_SIZE, &read, NULL) && read > 0) {
            int enc_len = 0;
            unsigned char* enc = pipen(buffer, read, SHARED_KEY, prev_iv, &enc_len);
            if (!enc) { CloseHandle(hFile); goto cleanup; }

            WinHttpWriteData(r, enc, enc_len, &written);
            memcpy(prev_iv, enc + enc_len - 16, 16);
            free(enc);
        }

        CloseHandle(hFile);
    } else if (prt->msg) {
        unsigned char iv[16]; RAND_bytes(iv, 16);
        int enc_len = 0;
        unsigned char* enc = pipen((unsigned char*)prt->msg, (int)strlen(prt->msg), SHARED_KEY, iv, &enc_len);
        if (!enc) goto cleanup;

        unsigned char* sendbuf = malloc(enc_len + 16);
        memcpy(sendbuf, iv, 16);
        memcpy(sendbuf + 16, enc, enc_len);
        ok = WinHttpSendRequest(r, L"Content-Type: application/octet-stream\r\n", -1,
                                sendbuf, enc_len + 16, enc_len + 16, 0);
        free(sendbuf); free(enc);
    }

    WinHttpReceiveResponse(r, NULL);

cleanup:
    WinHttpCloseHandle(r);
    WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);

    return ok ? (prt->file_switch ? "POST_FILE_OK" : "POST_MSG_OK") : NULL;
}

// ---------------- GET function ----------------
char* nino(https_t* prt) {
    if (!prt) return NULL;

    HINTERNET s = WinHttpOpen(L"Icarus", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return NULL;

    wchar_t wserver[256], wpath[512];
    MultiByteToWideChar(CP_ACP, 0, prt->server, -1, wserver, 256);
    MultiByteToWideChar(CP_ACP, 0, prt->fileserver, -1, wpath, 512);

    HINTERNET c = WinHttpConnect(s, wserver, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!c) { WinHttpCloseHandle(s); return NULL; }

    HINTERNET r = WinHttpOpenRequest(c, L"GET", wpath, NULL,
                                     WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!r) { WinHttpCloseHandle(c); WinHttpCloseHandle(s); return NULL; }

    WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(r, NULL);

    if (prt->file_switch && prt->files) {
        HANDLE hFile = CreateFileA(prt->files, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        if (!hFile || hFile == INVALID_HANDLE_VALUE) goto cleanup;

        unsigned char iv[16]; int iv_read = 0;
        unsigned char buffer[BLOCK_SIZE]; DWORD read;
        unsigned char prev_iv[16];

        while (WinHttpReadData(r, buffer, sizeof(buffer), &read) && read > 0) {
            unsigned char* data_ptr = buffer;
            DWORD data_len = read;

            if (iv_read < 16) {
                DWORD to_copy = min(16 - iv_read, read);
                memcpy(iv + iv_read, buffer, to_copy);
                iv_read += to_copy;
                if (iv_read < 16) continue;
                memcpy(prev_iv, iv, 16);
                data_ptr += to_copy;
                data_len -= to_copy;
                if (data_len == 0) continue;
            }

            int dec_len = 0;
            unsigned char* dec = sam(data_ptr, data_len, SHARED_KEY, prev_iv, &dec_len);
            if (!dec) goto cleanup;

            DWORD written;
            WriteFile(hFile, dec, dec_len, &written, NULL);
            memcpy(prev_iv, data_ptr + data_len - 16, 16);
            free(dec);
        }

        CloseHandle(hFile);
        WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
        return "GET_FILE_OK";
    } else {
        unsigned char iv[16]; int iv_read = 0;
        unsigned char buffer[BLOCK_SIZE]; DWORD read;
        unsigned char* total = NULL; size_t total_len = 0;

        while (WinHttpReadData(r, buffer, sizeof(buffer), &read) && read > 0) {
            unsigned char* data_ptr = buffer;
            DWORD data_len = read;

            if (iv_read < 16) {
                DWORD to_copy = min(16 - iv_read, read);
                memcpy(iv + iv_read, buffer, to_copy);
                iv_read += to_copy;
                if (iv_read < 16) continue;
                data_ptr += to_copy;
                data_len -= to_copy;
                if (data_len == 0) continue;
            }

            int dec_len = 0;
            unsigned char* dec = sam(data_ptr, data_len, SHARED_KEY, iv, &dec_len);
            if (!dec) goto cleanup;

            total = realloc(total, total_len + dec_len + 1);
            memcpy(total + total_len, dec, dec_len);
            total_len += dec_len;
            total[total_len] = 0;
            free(dec);
        }

        WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
        return (char*)total;
    }

cleanup:
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    return NULL;
}

// ---------------- Dispatcher ----------------
Icarus_API char* ituki(https_t* prt) {
    if (!prt) return NULL;
    return prt->get_post ? miku(prt) : nino(prt);
}


