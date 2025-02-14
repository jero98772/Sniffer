#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <time.h>
#include <netdb.h>      // for getnameinfo()

#define MAX_PACKETS 1024
#define DNS_NAME_SIZE NI_MAXHOST

// Structure to hold packet information
typedef struct PacketInfo {
    int packet_number;
    // Ethernet header info
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short eth_proto;
    // IP header info
    char src_ip[16];
    char dst_ip[16];
    unsigned int total_length;
    unsigned char ttl;
    unsigned char protocol;
    // Transport layer info (for TCP, example)
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq;
    unsigned int ack;
    unsigned char tcp_flags;
    // Reverse DNS (for source IP, for example)
    char src_dns[DNS_NAME_SIZE];
    // Payload info (optional)
    unsigned char *payload;
    int payload_size;
    // Capture timestamp
    time_t capture_time;
} PacketInfo;

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) void start_capture(void);
__attribute__((visibility("default"))) int get_packet_count(void);
__attribute__((visibility("default"))) PacketInfo* get_packet_info(int index);

#ifdef __cplusplus
}
#endif

#endif
