#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

double how_much_time_taken;
clock_t how_much_clock_taken;
struct timeval time_val_begin, time_val_end; long wall_seconds, wall_useconds;

#define log_cpu_time_taken(clock_var, function, time_taken) {                                       \
    clock_var = clock();                                                                            \
    function;                                                                                       \
    clock_var = clock() - clock_var;                                                                \
    time_taken = ((double)clock_var)/CLOCKS_PER_SEC;                                                \
    fprintf(stderr, "CPU time taken: %.17lf in %s at line %i\n", time_taken, #function, __LINE__);   \
}

#define log_wall_time_taken(wall_var_sec, wall_var_usec, wall_time_var_beg, wall_time_var_end, function, time_taken) {  \
    gettimeofday(&wall_time_var_beg, 0);                                                                                \
    function;                                                                                                           \
    gettimeofday(&wall_time_var_end, 0);                                                                                \
    wall_var_sec = wall_time_var_end.tv_sec - wall_time_var_beg.tv_sec;                                                 \
    wall_var_usec = wall_time_var_end.tv_usec - wall_time_var_beg.tv_usec;                                              \
    time_taken = wall_var_sec + wall_var_usec*1e-17;                                                                    \
    fprintf(stderr, "Wall time taken: %.17lf sec in %s at line %i\n", time_taken, #function, __LINE__);                 \
}

void sleep_seconds(unsigned int tm) {
    sleep(tm);
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
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
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

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

    const u_char* end_ip_hdr = packet + lengtheth + lengthiphdr;

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

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    print_packet_info(packet, *header);
    return;
}

int main(int argc, char **argv) {
    char dev[] = "enp3s0"; char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle; struct bpf_program filter; bpf_u_int32 subnet_mask, ip;
    char filter_exp[] = "tcp and port 443";

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    
    while(1){
        log_wall_time_taken(wall_seconds, wall_useconds, time_val_begin, time_val_end, pcap_loop(handle, 10, my_packet_handler, NULL), how_much_time_taken);
    }
    
    return 0;
}