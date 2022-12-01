// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sockfilter.h"
#include "sockfilter.skel.h"
#include "../../../poorpcap/filtering_rules.h"

static int fm = -1;

static const char * ipproto_mapping[IPPROTO_MAX] = {
	[IPPROTO_IP] = "IP",
	[IPPROTO_ICMP] = "ICMP",
	[IPPROTO_IGMP] = "IGMP",
	[IPPROTO_IPIP] = "IPIP",
	[IPPROTO_TCP] = "TCP",
	[IPPROTO_EGP] = "EGP",
	[IPPROTO_PUP] = "PUP",
	[IPPROTO_UDP] = "UDP",
	[IPPROTO_IDP] = "IDP",
	[IPPROTO_TP] = "TP",
	[IPPROTO_DCCP] = "DCCP",
	[IPPROTO_IPV6] = "IPV6",
	[IPPROTO_RSVP] = "RSVP",
	[IPPROTO_GRE] = "GRE",
	[IPPROTO_ESP] = "ESP",
	[IPPROTO_AH] = "AH",
	[IPPROTO_MTP] = "MTP",
	[IPPROTO_BEETPH] = "BEETPH",
	[IPPROTO_ENCAP] = "ENCAP",
	[IPPROTO_PIM] = "PIM",
	[IPPROTO_COMP] = "COMP",
	[IPPROTO_SCTP] = "SCTP",
	[IPPROTO_UDPLITE] = "UDPLITE",
	[IPPROTO_MPLS] = "MPLS",
	[IPPROTO_RAW] = "RAW"
};

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

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;
	char ifname[IF_NAMESIZE];

	if (e->pkt_type != PACKET_HOST)
		return 0;

	if (e->ip_proto < 0 || e->ip_proto >= IPPROTO_MAX)
		return 0;

	if (!if_indextoname(e->ifindex, ifname))
		return 0;

	printf("interface: %s\tprotocol: %s\t%s:%d(src) -> %s:%d(dst)\n",
		ifname,
		ipproto_mapping[e->ip_proto],
		inet_ntoa((struct in_addr){e->src_addr}),
		ntohs(e->port16[0]),
		inet_ntoa((struct in_addr){e->dst_addr}),
		ntohs(e->port16[1])
	);
	return 0;
}

static void updatefilters(struct filter *filterarr)
{
    // Loop through all filters and delete the map.
    for (__u8 i = 0; i < MAX_FILTERS; i++)
    {
        __u32 key = i;

        bpf_map_delete_elem(fm, &key);
    }

    // Add a filter to the filter maps.
    for (__u32 i = 0; i < MAX_FILTERS; i++)
    {
        // Check if we have a valid ID.
        if (filterarr[i].id < 1)
        {
            break;
        }

        // Attempt to update BPF map.
        if (bpf_map_update_elem(fm, &i, &filterarr[i], BPF_ANY) == -1)
        {
            fprintf(stderr, "Error updating BPF item #%d\n", i);
        }
    }
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct sockfilter_bpf *skel;
	int err, prog_fd, sock;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF programs*/
	skel = sockfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	fm = bpf_map__fd(skel->maps.filters_map);
	if (!fm) {
		err = -1;
		fprintf(stderr, "Failed to retrieve filters map\n");
		goto cleanup;
	}

	/* Create raw socket for localhost interface */
	sock = open_raw_sock("enp5s0f0");
	if (sock < 0) {
		err = -2;
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}

	/* Attach BPF program to raw socket */
	prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	updatefilters(filtering_rules_array);

	/* Process events */
	while (!exiting) {
		/*log_wall_time_taken (
			wall_seconds,wall_useconds,
			time_val_begin, time_val_end,
			err = ring_buffer__poll(rb, 100);, timeout, ms
			how_much_time_taken
		);*/
		err = ring_buffer__poll(rb, 100); /* timeout, ms */
		
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}

cleanup:
	ring_buffer__free(rb);
	sockfilter_bpf__destroy(skel);
	return -err;
}
