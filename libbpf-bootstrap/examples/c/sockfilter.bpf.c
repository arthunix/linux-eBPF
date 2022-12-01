// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockfilter.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

#define PASS -1
#define DROP 0

#define _DEBUG

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256 * 1024);
	__type(key, __u32);
	__type(value, struct filter);
} filters_map SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;
	__u128 srcip6 = 0;
    __u64 pps = 0; __u64 bps = 0;
	__u8 action = 0; __u64 blocktime = 1;
	int IP_HLEN;

	struct ethhdr ethdr = {0};
	struct iphdr iphdr = {0};
	struct ipv6hdr ipv6hdr = {0};
	struct tcphdr tcphdr = {0};
	struct udphdr udphdr = {0};
	struct icmphdr icmphdr = {0};
	struct icmp6hdr icmp6hdr = {0};

	int is_ipv4 = 0;
	int is_ipv6 = 0;
    int is_tcp = 0;
	int is_udp = 0;
	int is_icmp = 0;
	int is_icmpv6 = 0;

	bpf_skb_load_bytes(skb, 0, &ethdr, sizeof(ethdr));
    if (ethdr.h_proto == __bpf_htons(ETH_P_IPV6))
    {
#ifdef _DEBUG
        bpf_printk("HELLO IM A IP V6\n");
#endif
		bpf_skb_load_bytes(skb, ETH_HLEN, &ipv6hdr, sizeof(ipv6hdr));
        __builtin_memcpy(&srcip6, &ipv6hdr.saddr.in6_u.u6_addr32, sizeof(srcip6));
		is_ipv6 = 1;
		switch (ipv6hdr.nexthdr)
        {
            case IPPROTO_TCP:
                is_tcp = 1;
				bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr), &tcphdr, sizeof(struct ipv6hdr));
                break;
            case IPPROTO_UDP:
                is_udp = 1;
                bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr), &udphdr, sizeof(struct udphdr));
                break;
            case IPPROTO_ICMPV6:
                is_icmpv6 = 1;
                bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr), &icmp6hdr, sizeof(struct icmp6hdr));
                break;
			default:
				return DROP;
        }
    }
	else if (ethdr.h_proto == __bpf_htons(ETH_P_IP))
    {
#ifdef _DEBUG
        bpf_printk("HELLO IM A IP V4\n");
#endif
		bpf_skb_load_bytes(skb, ETH_HLEN, &iphdr, sizeof(iphdr));
		is_ipv4 = 1;
		switch (iphdr.protocol)
        {
            case IPPROTO_TCP:
                is_tcp = 1;
				bpf_skb_load_bytes(skb, ETH_HLEN + (iphdr.ihl * 4), &tcphdr, sizeof(struct ipv6hdr));
                break;
            case IPPROTO_UDP:
                is_udp = 1;
                bpf_skb_load_bytes(skb, ETH_HLEN + (iphdr.ihl * 4), &udphdr, sizeof(struct udphdr));
                break;
            case IPPROTO_ICMP:
                bpf_skb_load_bytes(skb, ETH_HLEN + (iphdr.ihl * 4), &icmphdr, sizeof(struct icmphdr));
				is_icmp = 1;
                break;
			default:
				return DROP;
        }
    }
    else {
        return DROP;
    }

	__u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *blocked = NULL;
    
    for (__u8 i = 0; i < MAX_FILTERS; i++)
    {
        __u32 key = i;
        struct filter *filter = bpf_map_lookup_elem(&filters_map, &key);

        // Check if ID is above 0 (if 0, it's an invalid rule).
        if (!filter || filter->id < 1)
        {
            break;
        }

#ifdef _DEBUG
        //bpf_printk("Testing rule ID #%d.\n", filter->id);
#endif

        // Check if the rule is enabled.
        if (!filter->enabled)
        {
#ifdef _DEBUG
        bpf_printk("THE FILTER IS ENABLED\n");
        bpf_printk("IS IPV4:    %i\n", is_ipv4);
        bpf_printk("IS IPV6:    %i\n", is_ipv6);
        bpf_printk("IS TCP:     %i\n", is_tcp);
        bpf_printk("IS UDP:     %i\n", is_udp);
        bpf_printk("IS ICMP:    %i\n", is_icmp);
        bpf_printk("IS ICMP6:   %i\n", is_icmpv6);
        bpf_printk("IS TCP-OPTS:     %i\n", filter->tcpopts.enabled);
        bpf_printk("IS UDP-OPTS:     %i\n", filter->udpopts.enabled);
        bpf_printk("IS ICMP-OPTS:    %i\n", filter->icmpopts.enabled);
#endif
            continue;
        }

        // Do specific IPv6.
        if (is_ipv6)
        {
#ifdef _DEBUG
        bpf_printk("THE FILTER IS FILTERING AN IPV6 PACKET\n");
#endif
            // Source address.
            if (filter->srcip6[0] != 0 && 
			(ipv6hdr.saddr.in6_u.u6_addr32[0] != filter->srcip6[0] || 
			 ipv6hdr.saddr.in6_u.u6_addr32[1] != filter->srcip6[1] ||
			 ipv6hdr.saddr.in6_u.u6_addr32[2] != filter->srcip6[2] ||
			 ipv6hdr.saddr.in6_u.u6_addr32[3] != filter->srcip6[3] )
            )
            {
                continue;
            }

            // Destination address.
            if (filter->dstip6[0] != 0 && 
			(ipv6hdr.daddr.in6_u.u6_addr32[0] != filter->dstip6[0] ||
			 ipv6hdr.daddr.in6_u.u6_addr32[1] != filter->dstip6[1] ||
			 ipv6hdr.daddr.in6_u.u6_addr32[2] != filter->dstip6[2] ||
			 ipv6hdr.daddr.in6_u.u6_addr32[3] != filter->dstip6[3] ))
            {
                continue;
            }

            // Max TTL length.
            if (filter->do_max_ttl && filter->max_ttl > ipv6hdr.hop_limit)
            {
                continue;
            }

            // Min TTL length.
            if (filter->do_min_ttl && filter->min_ttl < ipv6hdr.hop_limit)
            {
                continue;
            }

            // Max packet length.
            if (filter->do_max_len && filter->max_len > (__bpf_ntohs(ipv6hdr.payload_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter->do_min_len && filter->min_len < (__bpf_ntohs(ipv6hdr.payload_len) + sizeof(struct ethhdr)))
            {
                continue;
            }
        }
        else if (is_ipv4)
        {
#ifdef _DEBUG
        bpf_printk("THE FILTER IS FILTERING AN IPV4 PACKET\n");
#endif
            // Source address.
            if (filter->srcip && iphdr.saddr != filter->srcip)
            {
                continue;
            }

            // Destination address.
            if (filter->dstip && iphdr.daddr != filter->dstip)
            {
                continue;
            }

            // TOS.
            if (filter->do_tos && filter->tos != iphdr.tos)
            {
                continue;
            }

            // Max TTL length.
            if (filter->do_max_ttl && filter->max_ttl < iphdr.ttl)
            {
                continue;
            }

            // Min TTL length.
            if (filter->do_min_ttl && filter->min_ttl > iphdr.ttl)
            {
                continue;
            }

            // Max packet length.
            if (filter->do_max_len && filter->max_len < (__bpf_ntohs(iphdr.tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter->do_min_len && filter->min_len > (__bpf_ntohs(iphdr.tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }
        }
        
        // Do TCP options.
        if (filter->tcpopts.enabled)
        {
            if (is_tcp)
            {
#ifdef _DEBUG
                bpf_printk("HELLO IM A TCP PACKET\n");
#endif
                // Source port.
                if (filter->tcpopts.do_sport && __bpf_htons(filter->tcpopts.sport) != tcphdr.source)
                {
                    continue;
                }

                // Destination port.
                if (filter->tcpopts.do_dport && __bpf_htons(filter->tcpopts.dport) != tcphdr.dest)
                {
                    continue;
                }

                // URG flag.
                if (filter->tcpopts.do_urg && filter->tcpopts.urg != tcphdr.urg)
                {
                    continue;
                }

                // ACK flag.
                if (filter->tcpopts.do_ack && filter->tcpopts.ack != tcphdr.ack)
                {
                    continue;
                }

                // RST flag.
                if (filter->tcpopts.do_rst && filter->tcpopts.rst != tcphdr.rst)
                {
                    continue;
                }

                // PSH flag.
                if (filter->tcpopts.do_psh && filter->tcpopts.psh != tcphdr.psh)
                {
                    continue;
                }

                // SYN flag.
                if (filter->tcpopts.do_syn && filter->tcpopts.syn != tcphdr.syn)
                {
                    continue;
                }

                // FIN flag.
                if (filter->tcpopts.do_fin && filter->tcpopts.fin != tcphdr.fin)
                {
                    continue;
                }

                // ECE flag.
                if (filter->tcpopts.do_ece && filter->tcpopts.ece != tcphdr.ece)
                {
                    continue;
                }

                // CWR flag.
                if (filter->tcpopts.do_cwr && filter->tcpopts.cwr != tcphdr.cwr)
                {
                    continue;
                }
            }
            else {
                continue;
            }
        }
        else if (filter->udpopts.enabled)
        {
            if (is_udp)
            {
#ifdef _DEBUG
                bpf_printk("HELLO IM A UDP PACKET\n");
#endif
                // Source port.
                if (filter->udpopts.do_sport && __bpf_htons(filter->udpopts.sport) != udphdr.source)
                {
                    continue;
                }

                // Destination port.
                if (filter->udpopts.do_dport && __bpf_htons(filter->udpopts.dport) != udphdr.dest)
                {

                    continue;
                }
            }
            else {
                continue;
            }
        }
        else if (filter->icmpopts.enabled)
        {
            if (is_icmp)
            {
#ifdef _DEBUG
                bpf_printk("HELLO IM A ICMP PACKET\n");
#endif
                // Code.
                if (filter->icmpopts.do_code && filter->icmpopts.code != icmphdr.code)
                {
                    continue;
                }

                // Type.
                if (filter->icmpopts.do_type && filter->icmpopts.type != icmphdr.type)
                {
                    continue;
                }  
            }
            else if (is_icmpv6)
            {
                // Code.
                if (filter->icmpopts.do_code && filter->icmpopts.code != icmp6hdr.icmp6_code)
                {
                    continue;
                }

                // Type.
                if (filter->icmpopts.do_type && filter->icmpopts.type != icmp6hdr.icmp6_type)
                {
                    continue;
                }
            }
            else {
                continue;
            }
        }
#ifdef _DEBUG
        bpf_printk("Matched rule ID #%d.\n", filter->id);
#endif
        
        action = filter->action;
        blocktime = filter->blocktime;

        goto matched;
    }

notmatched:
#ifdef _DEBUG
    bpf_printk("NO MATCH TO ANY RULE\n");
#endif
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP)
        return 0;

    if (ip_is_fragment(skb, nhoff))
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

    if (e->ip_proto != IPPROTO_GRE) {
        bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
        bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
    }

    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;
    bpf_ringbuf_submit(e, 0);

    return skb->len;
    return PASS;

matched:
    if (action == 0) {
#ifdef _DEBUG
        bpf_printk("MATCHED TO A RULE: DROPPING\n");
#endif
        if (blocktime > 0) {
            __u64 newTime = now + (blocktime * 1000000000);
        }
        return DROP;
    } else {
#ifdef _DEBUG
        bpf_printk("MATCHED TO A RULE: BUT THE DROP IS DISABLED\n");
#endif
        goto notmatched;
        return PASS;
    }
}
