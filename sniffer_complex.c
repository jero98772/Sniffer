#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <unistd.h>

// Protocol definitions
#define ICMP 1
#define TCP  6
#define UDP  17

// Packet counter
static int packet_count = 0;

// Function to print packet payload data
void print_payload(unsigned char* data, int size) {
    int i, j;
    for(i = 0; i < size; i++) {
        if(i != 0 && i % 16 == 0) {
            printf("         ");
            for(j = i-16; j < i; j++) {
                if(data[j] >= 32 && data[j] <= 128)
                    printf("%c", (unsigned char)data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
        
        if(i % 16 == 0) printf("   ");
        printf(" %02X", (unsigned int)data[i]);
        
        if(i == size-1) {
            for(j = 0; j < 15 - i % 16; j++) printf("   ");
            printf("         ");
            for(j = i - i % 16; j <= i; j++) {
                if(data[j] >= 32 && data[j] <= 128)
                    printf("%c", (unsigned char)data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

// Function to print TCP packet details
void print_tcp_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    printf("\n\n***********************TCP Packet*************************\n");
    
    // Print IP header
    printf("\nIP Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d Bytes\n", ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n", ntohs(iph->id));
    printf("   |-TTL              : %d\n", (unsigned int)iph->ttl);
    printf("   |-Protocol         : %d\n", (unsigned int)iph->protocol);
    printf("   |-Checksum         : %d\n", ntohs(iph->check));
    
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    
    printf("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
    
    // Print TCP header
    printf("\nTCP Header\n");
    printf("   |-Source Port      : %u\n", ntohs(tcph->source));
    printf("   |-Destination Port : %u\n", ntohs(tcph->dest));
    printf("   |-Sequence Number  : %u\n", ntohl(tcph->seq));
    printf("   |-Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
    printf("   |-Header Length    : %d DWORDS or %d BYTES\n",
           (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
    
    // TCP Flags
    printf("   |-Urgent Flag      : %d\n", (unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag: %d\n", (unsigned int)tcph->ack);
    printf("   |-Push Flag        : %d\n", (unsigned int)tcph->psh);
    printf("   |-Reset Flag       : %d\n", (unsigned int)tcph->rst);
    printf("   |-Synchronise Flag : %d\n", (unsigned int)tcph->syn);
    printf("   |-Finish Flag      : %d\n", (unsigned int)tcph->fin);
    printf("   |-Window Size      : %d\n", ntohs(tcph->window));
    printf("   |-Checksum         : %d\n", ntohs(tcph->check));
    printf("   |-Urgent Pointer   : %d\n", tcph->urg_ptr);
    
    // Print payload data
    printf("\nPayload Data: \n");
    int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
    int payload_size = size - header_size;
    if(payload_size > 0) {
        print_payload(buffer + header_size, payload_size);
    }
    
    printf("\n###########################################################\n");
}

// Function to handle UDP packets
void print_udp_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    printf("\n\n***********************UDP Packet*************************\n");
    
    // Print IP header (similar to TCP)
    printf("\nIP Header\n");
    // ... (similar IP header printing as in TCP)
    
    // Print UDP header
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n", ntohs(udph->source));
    printf("   |-Destination Port : %d\n", ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));
    
    // Print payload
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
    int payload_size = size - header_size;
    if(payload_size > 0) {
        printf("\nPayload Data: \n");
        print_payload(buffer + header_size, payload_size);
    }
    
    printf("\n###########################################################\n");
}

// Function to process incoming packets
void process_packet(unsigned char* buffer, int size) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    packet_count++;
    printf("\nPacket Number: %d\n", packet_count);
    
    // Print Ethernet header
    printf("\nEthernet Header\n");
    printf("   |-Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Source MAC     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Protocol       : %d\n", (unsigned short)eth->h_proto);
    
    switch(iph->protocol) {
        case ICMP:
            printf("Protocol: ICMP\n");
            // Add ICMP packet handling if needed
            break;
        case TCP:
            print_tcp_packet(buffer, size);
            break;
        case UDP:
            print_udp_packet(buffer, size);
            break;
        default:
            printf("Protocol: Others\n");
            break;
    }
}

int main() {
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_raw < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    
    printf("Starting Advanced Packet Capture...\n");
    printf("Press Ctrl+C to stop.\n\n");
    
    while(1) {
        int buflen = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if(buflen < 0) {
            printf("Failed to get packets\n");
            continue;
        }
        process_packet(buffer, buflen);
    }
    
    close(sock_raw);
    free(buffer);
    return 0;
}