#ifndef __FILTERINGRULES_H
#define __FILTERINGRULES_H

#define MAX_FILTERS 100
#define MAX_TRACK_IPS 100000
#define MAX_CPUS 256

#define EBPF_DROP 0
#define EBPF_PASS 1

#define DEBUG

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
    unsigned int enabled;
    unsigned int do_sport; __u16 sport;
    unsigned int do_dport; __u16 dport;
    unsigned int do_urg; unsigned int urg;
    unsigned int do_ack; unsigned int ack;
    unsigned int do_rst; unsigned int rst;
    unsigned int do_psh; unsigned int psh;
    unsigned int do_syn; unsigned int syn;
    unsigned int do_fin; unsigned int fin;
    unsigned int do_ece; unsigned int ece;
    unsigned int do_cwr; unsigned int cwr;
};

struct udpopts
{
    unsigned int enabled ;
    unsigned int do_sport; __u16 sport;
    unsigned int do_dport; __u16 dport;
};

struct icmpopts
{
    unsigned int enabled;
    unsigned int do_code; __u8 code;
    unsigned int do_type; __u8 type;
};

struct filter
{
    unsigned int enabled : 1;
    __u8 id; __u8 action;
    __u32 srcip; __u32 dstip;
    __u32 srcip6[4]; __u32 dstip6[4];

    unsigned int do_min_ttl; __u8  min_ttl;
    unsigned int do_max_ttl; __u8  max_ttl;
    unsigned int do_min_len; __u16 min_len;
    unsigned int do_max_len; __u16 max_len;
    unsigned int do_tos; __u8  tos;
    unsigned int do_pps; __u64 pps;
    unsigned int do_bps; __u64 bps;

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

static struct filter filtering_rules_array[] = {
	{
		.id = 1,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 21 /* FTP */
	},
    {
		.id = 2,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 22 /* SSH */
	},
    {
		.id = 3,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 23 /* TELNET */
	},
    {
		.id = 4,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 25 /* SMTP */
	},
    {
		.id = 5,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 43 /* WHOIS */
	},
    {
		.id = 6,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 53 /* DNS */
	},
    {
		.id = 7,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.do_dport = 1,
		.udpopts.dport = 67 /* DHCP */
	},
	{
		.id = 8,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.do_dport = 1,
		.udpopts.dport = 68 /* DHCP */
	},
    {
		.id = 9,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 80 /* HTTP */
	},
    {
		.id = 10,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.do_dport = 1,
		.udpopts.dport = 80 /* HTTP */
	},
    {
		.id = 11,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 110 /* POP3 */
	},
    {
		.id = 12,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 115 /* FTP */
	},
    {
		.id = 13,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 143 /* IMAP */
	},
    {
		.id = 14,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 443 /* HTTPS */
	},
    {
		.id = 15,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 443 /* HTTPS */
	},
    {
		.id = 16,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 587 /* SMTP SSL */
	},
    {
		.id = 17,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_dport = 1,
		.tcpopts.dport = 993 /* IMAP SSL */
	},
	{
		.id = 21,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 21 /* FTP */
	},
    {
		.id = 22,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 22 /* SSH */
	},
    {
		.id = 23,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 23 /* TELNET */
	},
    {
		.id = 24,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 25 /* SMTP */
	},
    {
		.id = 25,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 43 /* WHOIS */
	},
    {
		.id = 26,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 53 /* DNS */
	},
    {
		.id = 27,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.do_sport = 1,
		.udpopts.sport = 67 /* DHCP */
	},
	{
		.id = 28,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.do_sport = 1,
		.udpopts.sport = 68 /* DHCP */
	},
    {
		.id = 29,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 80 /* HTTP */
	},
    {
		.id = 30,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.do_sport = 1,
		.udpopts.sport = 80 /* HTTP */
	},
    {
		.id = 31,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 110 /* POP3 */
	},
    {
		.id = 32,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 115 /* FTP */
	},
    {
		.id = 33,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 143 /* IMAP */
	},
    {
		.id = 34,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 443 /* HTTPS */
	},
    {
		.id = 35,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 443 /* HTTPS */
	},
    {
		.id = 36,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 587 /* SMTP SSL */
	},
    {
		.id = 37,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.do_sport = 1,
		.tcpopts.sport = 993 /* IMAP SSL */
	},
    /* ANOTHER FILTERING RULES */
    {
		.id = 41,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 36949814,        /* ava2.ead.ufscar.br */
        .srcip = 36949814         /* ava2.ead.ufscar.br */
	},
    {
		.id = 42,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 676391354,      /* ava2.ead.ufscar.br */
        .srcip = 676391354       /* ava2.ead.ufscar.br */
	},
    {
		.id = 43,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 2060421320,    /* ava2.ead.ufscar.br */
        .srcip = 2060421320     /* ava2.ead.ufscar.br */
	},
    {
		.id = 44,
		.enabled = 0,
		.action = 0, /* DROP */
        .dstip = 1008258870,       /* ava2.ead.ufscar.br */
        .srcip = 1008258870        /* ava2.ead.ufscar.br */
	}
};

#endif // __FILTERINGRULES_H