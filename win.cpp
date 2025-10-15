// receiver_windows.cpp
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cstdint>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#define CUSTOM_ETHER_TYPE 0x88B5

struct EthernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t ethertype;
};

std::map<uint32_t, std::vector<uint8_t>> fileChunks;
bool lastChunkReceived = false;

// Packet handler callback
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->len < sizeof(EthernetHeader) + 5) return;

    EthernetHeader* eth = (EthernetHeader*)packet;
    uint16_t eth_type = ntohs(eth->ethertype);

    if (eth_type == CUSTOM_ETHER_TYPE) {
        const u_char* payload = packet + sizeof(EthernetHeader);
        uint32_t seq = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
        uint8_t flags = payload[4];
        std::vector<uint8_t> data(payload + 5, payload + pkthdr->len - sizeof(EthernetHeader));

        fileChunks[seq] = data;

        std::cout << "Received chunk seq=" << seq << ", size=" << data.size() << " bytes\n";

        if (flags & 1) {
            lastChunkReceived = true;
            std::cout << "Last chunk detected.\n";
        }
    }
}

int main(int argc, char* argv[]) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <output_file>\n";
        return 1;
    }

    const char* dev = argv[1];
    const char* outFile = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65536, 1, 10, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Listening on " << dev << " for EtherType 0x" 
              << std::hex << CUSTOM_ETHER_TYPE << std::dec << "...\n";

    while (!lastChunkReceived) {
        pcap_dispatch(handle, 1, packetHandler, nullptr);
    }

    std::cout << "Reassembling file...\n";

    std::ofstream ofs(outFile, std::ios::binary);
    for (size_t i = 0; i < fileChunks.size(); ++i) {
        auto it = fileChunks.find((uint32_t)i);
        if (it != fileChunks.end()) {
            ofs.write((char*)it->second.data(), it->second.size());
        }
    }
    ofs.close();

    std::cout << "File saved to " << outFile << "\n";

    pcap_close(handle);
    WSACleanup();
    return 0;
}
