#ifndef __SOCKFILTER_H
#define __SOCKFILTER_H

#include <linux/types.h>
#include <netinet/in.h>

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

static __be32 in_aton(const char *str)
{
	unsigned int l;
	unsigned int val;
	int i;

	l = 0;
	for (i = 0; i < 4; i++)	{
		l <<= 8;
		if (*str != '\0') {
			val = 0;
			while (*str != '\0' && *str != '.' && *str != '\n') {
				val *= 10;
				val += *str - '0';
				str++;
			}
			l |= val;
			if (*str != '\0')
				str++;
		}
	}
	return htonl(l);
}

static struct filter filtering_rules_array[] = {
	{
		.id = 1,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 21 /* FTP */
	},
    {
		.id = 2,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 22 /* SSH */
	},
    {
		.id = 3,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 23 /* TELNET */
	},
    {
		.id = 4,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 25 /* SMTP */
	},
    {
		.id = 5,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 43 /* WHOIS */
	},
    {
		.id = 6,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 53 /* DNS */
	},
    {
		.id = 7,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.dport = 67 /* DHCP */
	},
	{
		.id = 8,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.dport = 68 /* DHCP */
	},
    {
		.id = 9,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 80 /* HTTP */
	},
    {
		.id = 10,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.dport = 80 /* HTTP */
	},
    {
		.id = 11,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 110 /* POP3 */
	},
    {
		.id = 12,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 115 /* FTP */
	},
    {
		.id = 13,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 143 /* IMAP */
	},
    {
		.id = 14,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 443 /* HTTPS */
	},
    {
		.id = 15,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 443 /* HTTPS */
	},
    {
		.id = 16,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 587 /* SMTP SSL */
	},
    {
		.id = 17,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.dport = 993 /* IMAP SSL */
	},
	{
		.id = 21,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 21 /* FTP */
	},
    {
		.id = 22,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 22 /* SSH */
	},
    {
		.id = 23,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 23 /* TELNET */
	},
    {
		.id = 24,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 25 /* SMTP */
	},
    {
		.id = 25,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 43 /* WHOIS */
	},
    {
		.id = 26,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 53 /* DNS */
	},
    {
		.id = 27,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.sport = 67 /* DHCP */
	},
	{
		.id = 28,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.sport = 68 /* DHCP */
	},
    {
		.id = 29,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 80 /* HTTP */
	},
    {
		.id = 30,
		.enabled = 0,
		.action = 0, /* DROP */
		.udpopts.enabled = 1,
		.udpopts.sport = 80 /* HTTP */
	},
    {
		.id = 31,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 110 /* POP3 */
	},
    {
		.id = 32,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 115 /* FTP */
	},
    {
		.id = 33,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 143 /* IMAP */
	},
    {
		.id = 34,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 443 /* HTTPS */
	},
    {
		.id = 35,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 443 /* HTTPS */
	},
    {
		.id = 36,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
		.tcpopts.sport = 587 /* SMTP SSL */
	},
    {
		.id = 37,
		.enabled = 0,
		.action = 0, /* DROP */
		.tcpopts.enabled = 1,
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

#endif // __SOCKFILTER_H