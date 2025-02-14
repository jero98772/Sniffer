#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// Function to analyze TCP flags
void analyze_tcp_flags(unsigned char flags) {
    printf("TCP Flags: ");
    if (flags & TH_FIN) printf("FIN ");
    if (flags & TH_SYN) printf("SYN ");
    if (flags & TH_RST) printf("RST ");
    if (flags & TH_PUSH) printf("PUSH ");
    if (flags & TH_ACK) printf("ACK ");
    if (flags & TH_URG) printf("URG ");
    printf("\n");
}

int main() {
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket creation error");
        return 1;
    }

    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    printf("Starting packet capture...\n");

    while (1) {
        int buflen = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (buflen < 0) {
            printf("Error receiving packets\n");
            continue;
        }

        // Skip Ethernet header
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        
        // Check if it's a TCP packet
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
            
            printf("\n\n=== TCP Packet Captured ===\n");
            
            // Print source and destination IP
            struct sockaddr_in source, dest;
            memset(&source, 0, sizeof(source));
            memset(&dest, 0, sizeof(dest));
            
            source.sin_addr.s_addr = iph->saddr;
            dest.sin_addr.s_addr = iph->daddr;
            
            printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
            printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
            
            // Print ports
            printf("Source Port: %d\n", ntohs(tcph->source));
            printf("Destination Port: %d\n", ntohs(tcph->dest));
            
            // Analyze TCP flags
            analyze_tcp_flags(tcph->th_flags);
            
            printf("Sequence Number: %u\n", ntohl(tcph->seq));
            printf("Acknowledgement Number: %u\n", ntohl(tcph->ack_seq));
            printf("======================\n");
        }
    }
    
    close(sock_raw);
    free(buffer);
    return 0;
}