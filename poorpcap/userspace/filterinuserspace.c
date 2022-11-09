#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

double how_much_time_taken; struct timeval time_val_beg, time_val_end; long how_much_time_sec, how_much_time_usec;

#define log_wall_time_taken(how_much_time_sec, how_much_time_usec, wall_time_var_beg, wall_time_var_end, function, time_taken) {    \
    gettimeofday(&wall_time_var_beg, 0);                                                                                            \
    function;                                                                                                                       \
    gettimeofday(&wall_time_var_end, 0);                                                                                            \
    how_much_time_sec = wall_time_var_end.tv_sec - wall_time_var_beg.tv_sec;                                                        \
    how_much_time_usec = wall_time_var_end.tv_usec - wall_time_var_beg.tv_usec;                                                     \
    time_taken = wall_var_sec + wall_var_usec*1e-10;                                                                                \
    fprintf(stderr, "Wall time taken: %.5lf sec in %s at line %i\n", time_taken, #function, __LINE__);                              \
}

void sleep_seconds(unsigned int tm) {
    sleep(tm);
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("packet capture length: %d | packet total length %d\n", packet_header.caplen, packet_header.len);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    print_packet_info(packet, *header);
    return;
}

int main(int argc, char **argv) {
    char dev[] = "enp3s0";
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "tcp and port 80";
    bpf_u_int32 subnet_mask, ip;

    double how_much_time_taken;
    clock_t how_much_clock_taken;
    struct timeval time_val_begin, time_val_end; long wall_seconds, wall_useconds;

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

    log_cpu_time_taken(how_much_clock_taken, pcap_loop(handle, 10, my_packet_handler, NULL), how_much_time_taken);

    return 0;
}