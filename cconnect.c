// bare_metal_file_receiver.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>

#define CUSTOM_ETHER_TYPE 0x88B5
#define MAX_CHUNKS 10000

typedef struct {
    int seq;
    size_t size;
    unsigned char *data;
} Chunk;

Chunk fileChunks[MAX_CHUNKS];
int lastChunkReceived = 0;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <interface> <output_file>\n", argv[0]);
        return 1;
    }

    char *iface = argv[1];
    char *outputFile = argv[2];

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(CUSTOM_ETHER_TYPE));
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Bind to interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(CUSTOM_ETHER_TYPE);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return 1;
    }

    printf("Listening on interface %s for EtherType 0x%04X\n", iface, CUSTOM_ETHER_TYPE);

    while (!lastChunkReceived) {
        unsigned char buffer[65536];
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 5) continue; // need at least seq(4) + flags(1)

        // Skip Ethernet header (14 bytes)
        if (len < 14 + 5) continue;
        unsigned char *payload = buffer + 14;
        int seq = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
        unsigned char flags = payload[4];
        size_t data_len = len - 14 - 5;

        if (seq >= MAX_CHUNKS) {
            fprintf(stderr, "Sequence number too large: %d\n", seq);
            continue;
        }

        fileChunks[seq].seq = seq;
        fileChunks[seq].size = data_len;
        fileChunks[seq].data = malloc(data_len);
        memcpy(fileChunks[seq].data, payload + 5, data_len);

        printf("Received chunk seq=%d, size=%zu bytes\n", seq, data_len);

        if (flags & 1) {
            lastChunkReceived = 1;
            printf("Last chunk detected.\n");
        }
    }

    // Reassemble file
    FILE *fp = fopen(outputFile, "wb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    for (int i = 0; i < MAX_CHUNKS; i++) {
        if (fileChunks[i].data) {
            fwrite(fileChunks[i].data, 1, fileChunks[i].size, fp);
            free(fileChunks[i].data);
        }
    }

    fclose(fp);
    close(sockfd);

    printf("File saved to %s\n", outputFile);
    return 0;
}
