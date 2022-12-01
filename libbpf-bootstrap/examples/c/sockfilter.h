// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#ifndef __SOCKFILTER_H
#define __SOCKFILTER_H

#define MAX_FILTERS 100
#define MAX_TRACK_IPS 100000
#define MAX_CPUS 256

#define __u128 __uint128_t

struct so_event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;
};

struct tcpopts
{
    unsigned int enabled : 1;

    unsigned int do_sport : 1; __u16 sport;
    unsigned int do_dport : 1; __u16 dport;
    unsigned int do_urg : 1; unsigned int urg : 1;
    unsigned int do_ack : 1; unsigned int ack : 1;
    unsigned int do_rst : 1; unsigned int rst : 1;
    unsigned int do_psh : 1; unsigned int psh : 1;
    unsigned int do_syn : 1; unsigned int syn : 1;
    unsigned int do_fin : 1; unsigned int fin : 1;
    unsigned int do_ece : 1; unsigned int ece : 1;
    unsigned int do_cwr : 1; unsigned int cwr : 1;
};

struct udpopts
{
    unsigned int enabled  : 1;
    unsigned int do_sport : 1; __u16 sport;
    unsigned int do_dport : 1; __u16 dport;
};

struct icmpopts
{
    unsigned int enabled : 1;
    unsigned int do_code : 1; __u8 code;
    unsigned int do_type : 1; __u8 type;
};

struct filter
{
    unsigned int enabled : 1;
    __u8 id; __u8 action;
    __u32 srcip; __u32 dstip;
    __u32 srcip6[4]; __u32 dstip6[4];

    unsigned int do_min_ttl : 1; __u8  min_ttl;
    unsigned int do_max_ttl : 1; __u8  max_ttl;
    unsigned int do_min_len : 1; __u16 min_len;
    unsigned int do_max_len : 1; __u16 max_len;
    unsigned int do_tos : 1; __u8  tos;
    unsigned int do_pps : 1; __u64 pps;
    unsigned int do_bps : 1; __u64 bps;

    __u64 blocktime;

    struct tcpopts tcpopts;
    struct udpopts udpopts;
    struct icmpopts icmpopts;
};

struct stats
{
    __u64 allowed;
    __u64 dropped;
};

struct ip_stats
{
    __u64 pps;
    __u64 bps;
    __u64 tracking;
};

#endif /* __SOCKFILTER_H */
