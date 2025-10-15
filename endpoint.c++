#include <iostream>
#include <string>
#include <curl/curl.h>
#include <Windows.h>

// Callback to capture response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

__declspec(dllexport) int main(std::string var1) {
    // The command you want to run
    std::string command = var1;
    
    // URL encode the command
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize curl\n";
        return 1;
    }

    char* encodedCommand = curl_easy_escape(curl, command.c_str(), command.length());
    std::string url = "change" + std::string(encodedCommand); // <-- server url here
    curl_free(encodedCommand);

    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
    } else {
        std::cout << "Server response:\n" << response << "\n";
    }

    curl_easy_cleanup(curl);
    return 0;
}