#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "../filtering_rules.h"

double how_much_time_taken; clock_t how_much_clock_taken; struct timeval time_val_begin, time_val_end; long wall_seconds, wall_useconds;

#define log_wall_time_taken(wall_var_sec, wall_var_usec, wall_time_var_beg, wall_time_var_end, function, time_taken) {  \
    gettimeofday(&wall_time_var_beg, 0);                                                                                \
    function;                                                                                                           \
    gettimeofday(&wall_time_var_end, 0);                                                                                \
    wall_var_sec = wall_time_var_end.tv_sec - wall_time_var_beg.tv_sec;                                                 \
    wall_var_usec = wall_time_var_end.tv_usec - wall_time_var_beg.tv_usec;                                              \
    time_taken = wall_var_sec + wall_var_usec*1e-17;                                                                    \
    fprintf(stderr, "Wall time taken: %.17lf sec in %s at line %i\n", time_taken, #function, __LINE__);                 \
}

void print_packet_info(const unsigned char *packet, struct pcap_pkthdr packet_header) {
    struct iphdr *iphdr = NULL;
    struct tcphdr *tcphdr = NULL;
    struct udphdr *udphdr = NULL;
    struct ether_header *ethhdr = NULL;

    ethhdr = (struct ether_header*) packet;

    if (ntohs(ethhdr->ether_type) != ETHERTYPE_IP) {
        printf(" ...Not an IP packet. Skipping...\n");
        return;
    }

    /* Pointers to start point of various headers */
    const unsigned char *ip_header;
    const unsigned char *tcp_header;
    const unsigned char *payload;

    int lengtheth = 14; /* Doesn't change */
    int lengthiphdr;
    int lengthtcphdr;
    int lengthpld;

    ip_header = packet + lengtheth;
    lengthiphdr = ((*ip_header) & 0x0F);
    lengthiphdr = lengthiphdr * 4;

    iphdr = (struct iphdr*)ip_header;
    

    struct in_addr src_address = { iphdr->saddr };
    struct in_addr dst_address = { iphdr->daddr };

    const unsigned char* end_ip_hdr = packet + lengtheth + lengthiphdr;

    udphdr = (struct udphdr*)end_ip_hdr;
    tcphdr = (struct tcphdr*)end_ip_hdr;
    u_int16_t src_port;
    u_int16_t dst_port;

    if(ntohs(iphdr->protocol) != IPPROTO_TCP) {
        printf("PROTOCOL: TCP ");
        src_port = tcphdr->source;
        dst_port = tcphdr->dest;
    }
    else if (ntohs(iphdr->protocol) != IPPROTO_UDP) {
        printf("PROTOCOL: UDP ");
        src_port = udphdr->source;
        dst_port = udphdr->dest;
    }
    else {
        printf(" ...Not an TCP/IP or UDP/IP packet. Skipping...\n");
        return;
    }

    printf("SRC IP: %s (SRC PORT: %i)", inet_ntoa(src_address), ntohs(src_port));
    printf("   DST IP: %s (DST PORT: %i) \n",  inet_ntoa(dst_address), ntohs(dst_port));
}

void my_packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    print_packet_info(packet, *header);
    return;
}

int main(int argc, char **argv) {
    if((argc >= 3) || (argc <= 1)) {
        fprintf(stderr,"The number of parameters is not correct\n");
        fprintf(stderr,"usage: ./socket_filter [interface]\n\n");
        return 0;
    }

    char* dev = argv[1];
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle; struct bpf_program filter; bpf_u_int32 subnet_mask, ip;

    char filter_exp[] = "tcp and port 443";

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        fprintf(stderr,"Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr,"Could not open %s - %s\n", dev, error_buffer);
        return 2;
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        fprintf(stderr,"Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr,"Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, 10, my_packet_handler, NULL);
    
    //while(1) { log_wall_time_taken(wall_seconds, wall_useconds, time_val_begin, time_val_end, pcap_loop(handle, 10, my_packet_handler, NULL), how_much_time_taken); }

    return 0;
}