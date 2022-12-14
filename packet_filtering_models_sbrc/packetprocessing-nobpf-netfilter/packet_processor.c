// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/time.h>
#include <linux/ktime.h>

#include "../filtering_rules.h"

#define MAX_PCKT_LENGTH 65535
#define MAX_FILTERS 100
#define MAX_TRACK_IPS 100000
#define MAX_CPUS 256

#define __u128 __uint128_t
#define _DEBUG

static char buffer[32];

char *
inet_ntoa_ipv4(struct in_addr in)
{
  unsigned char *bytes = (unsigned char *)&in;
  snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
  return buffer;
}

char *
inet_ntoa_ipv6(struct in6_addr in)
{
  unsigned char *bytes = (unsigned char *)&in;
  snprintf(buffer, sizeof(buffer), "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x", 
  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
  return buffer;
}

static unsigned int firewall_fun(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct ethhdr* ethhdrptr = NULL;
	struct iphdr* iphdrptr = NULL;
	struct ipv6hdr* ipv6hdrptr = NULL;
	struct tcphdr* tcphdrptr = NULL;
	struct udphdr* udphdrptr = NULL;
	struct icmphdr* icmphdrptr = NULL;
	struct icmp6hdr* icmpv6hdrptr = NULL;
	__u8 verlen; __u16 proto; __u32 nhoff = ETH_HLEN;
    __u64 now = ktime_get(); __u8 action = 0; __u64 blocktime = 1;

    __u128 srcip6 = 0; __u128 dstip6 = 0;

    ethhdrptr = eth_hdr(skb);
	
    printk("PACKET PROTOCOL: %i", ethhdrptr->h_proto);
	if((ethhdrptr->h_proto != htons(ETH_P_IP)) && (ethhdrptr->h_proto != htons(ETH_P_IPV6))) {
		printk("if(ethhdrptr->h_proto != htons(ETH_P_IP) && ethhdrptr->h_proto != htons(ETH_P_IPV6)) : PASSING");
        return NF_ACCEPT;
    }

	if (ethhdrptr->h_proto == htons(ETH_P_IPV6)) {
        ipv6hdrptr = ipv6_hdr(skb);

        memcpy(&srcip6, &ipv6hdrptr->saddr.in6_u.u6_addr32, sizeof(srcip6));
		memcpy(&dstip6, &ipv6hdrptr->daddr.in6_u.u6_addr32, sizeof(dstip6));

		printk("I am an ipv6 header : ");
		printk("daddr : %s", inet_ntoa_ipv6( ipv6hdrptr->daddr ));
		printk("saddr : %s", inet_ntoa_ipv6( ipv6hdrptr->saddr ));
    }
    else if (ethhdrptr->h_proto == htons(ETH_P_IP)) {
        iphdrptr = ip_hdr(skb);

		printk("I am an ipv4 header : ");
		printk("daddr : %s", inet_ntoa_ipv4( (struct in_addr){ iphdrptr->daddr } ) );
		printk("saddr : %s", inet_ntoa_ipv4( (struct in_addr){ iphdrptr->saddr } ) );
    }

    // Check IP header protocols.
    if((ipv6hdrptr && ipv6hdrptr->nexthdr != IPPROTO_UDP && ipv6hdrptr->nexthdr != IPPROTO_TCP && ipv6hdrptr->nexthdr != IPPROTO_ICMP) && 
    (iphdrptr && iphdrptr->protocol != IPPROTO_UDP && iphdrptr->protocol != IPPROTO_TCP && iphdrptr->protocol != IPPROTO_ICMP)) {
        return NF_ACCEPT;
    }

	if (ipv6hdrptr)
    {
        switch (ipv6hdrptr->nexthdr)
        {
            case IPPROTO_TCP:
                tcphdrptr = tcp_hdr(skb);
                break;
            case IPPROTO_UDP:
                udphdrptr = udp_hdr(skb);
                break;
            case IPPROTO_ICMPV6:
                icmpv6hdrptr = icmp6_hdr(skb);
                break;
        }
    }
    else if (iphdrptr)
    {
        switch (iphdrptr->protocol)
        {
            case IPPROTO_TCP:
                tcphdrptr = tcp_hdr(skb);
                break;
            case IPPROTO_UDP:
                udphdrptr = udp_hdr(skb);
                break;
            case IPPROTO_ICMP:
                icmphdrptr = icmp_hdr(skb);
                break;
        }
    }
    
    for (__u8 i = 0; i < MAX_FILTERS; i++)
    {
        __u32 key = i;
        struct filter *filter = &filtering_rules_array[key];

        // Check if ID is above 0 (if 0, it's an invalid rule).
        if (!filter || filter->id < 1)
        {
            break;
        }

        // Check if the rule is enabled.
        if (!filter->enabled)
        {
            continue;
        }

        // Do specific IPv6.
        if (ipv6hdrptr)
        {
            // Source address.
            if (filter->srcip6[0] != 0 && 
			(ipv6hdrptr->saddr.in6_u.u6_addr32[0] != filter->srcip6[0] 
			|| ipv6hdrptr->saddr.in6_u.u6_addr32[1] != filter->srcip6[1]
			|| ipv6hdrptr->saddr.in6_u.u6_addr32[2] != filter->srcip6[2] 
			|| ipv6hdrptr->saddr.in6_u.u6_addr32[3] != filter->srcip6[3]))
            {
                continue;
            }

            // Destination address.
            if (filter->dstip6[0] != 0 &&
			(ipv6hdrptr->daddr.in6_u.u6_addr32[0] != filter->dstip6[0]
			|| ipv6hdrptr->daddr.in6_u.u6_addr32[1] != filter->dstip6[1]
			|| ipv6hdrptr->daddr.in6_u.u6_addr32[2] != filter->dstip6[2]
			|| ipv6hdrptr->daddr.in6_u.u6_addr32[3] != filter->dstip6[3]))
            {
                continue;
            }

            // Max TTL length.
            if (filter->do_max_ttl && filter->max_ttl > ipv6hdrptr->hop_limit)
            {
                continue;
            }

            // Min TTL length.
            if (filter->do_min_ttl && filter->min_ttl < ipv6hdrptr->hop_limit)
            {
                continue;
            }

            // Max packet length.
            if (filter->do_max_len && filter->max_len > (ntohs(ipv6hdrptr->payload_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter->do_min_len && filter->min_len < (ntohs(ipv6hdrptr->payload_len) + sizeof(struct ethhdr)))
            {
                continue;
            }
        }
        else if (iphdrptr)
        {
            // Source address.
            if (filter->srcip && iphdrptr->saddr != filter->srcip)
            {
                continue;
            }

            // Destination address.
            if (filter->dstip != 0 && iphdrptr->daddr != filter->dstip)
            {
                continue;
            }

            // TOS.
            if (filter->do_tos && filter->tos != iphdrptr->tos)
            {
                continue;
            }

            // Max TTL length.
            if (filter->do_max_ttl && filter->max_ttl < iphdrptr->ttl)
            {
                continue;
            }

            // Min TTL length.
            if (filter->do_min_ttl && filter->min_ttl > iphdrptr->ttl)
            {
                continue;
            }

            // Max packet length.
            if (filter->do_max_len && filter->max_len < (ntohs(iphdrptr->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter->do_min_len && filter->min_len > (ntohs(iphdrptr->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }
        }
        
        // Do TCP options.
        if (filter->tcpopts.enabled)
        {
            if (!tcphdrptr)
            {
                continue;
            }

            // Source port.
            if (filter->tcpopts.do_sport && htons(filter->tcpopts.sport) != tcphdrptr->source)
            {
                continue;
            }

            // Destination port.
            if (filter->tcpopts.do_dport && htons(filter->tcpopts.dport) != tcphdrptr->dest)
            {
                continue;
            }

            // URG flag.
            if (filter->tcpopts.do_urg && filter->tcpopts.urg != tcphdrptr->urg)
            {
                continue;
            }

            // ACK flag.
            if (filter->tcpopts.do_ack && filter->tcpopts.ack != tcphdrptr->ack)
            {
                continue;
            }

            // RST flag.
            if (filter->tcpopts.do_rst && filter->tcpopts.rst != tcphdrptr->rst)
            {
                continue;
            }

            // PSH flag.
            if (filter->tcpopts.do_psh && filter->tcpopts.psh != tcphdrptr->psh)
            {
                continue;
            }

            // SYN flag.
            if (filter->tcpopts.do_syn && filter->tcpopts.syn != tcphdrptr->syn)
            {
                continue;
            }

            // FIN flag.
            if (filter->tcpopts.do_fin && filter->tcpopts.fin != tcphdrptr->fin)
            {
                continue;
            }

            // ECE flag.
            if (filter->tcpopts.do_ece && filter->tcpopts.ece != tcphdrptr->ece)
            {
                continue;
            }

            // CWR flag.
            if (filter->tcpopts.do_cwr && filter->tcpopts.cwr != tcphdrptr->cwr)
            {
                continue;
            }
        }
        else if (filter->udpopts.enabled)
        {
            if (!udphdrptr)
            {
                continue;
            }

            // Source port.
            if (filter->udpopts.do_sport && htons(filter->udpopts.sport) != udphdrptr->source)
            {
                continue;
            }

            // Destination port.
            if (filter->udpopts.do_dport && htons(filter->udpopts.dport) != udphdrptr->dest)
            {
                continue;
            }
        }
        else if (filter->icmpopts.enabled)
        {
            if (icmphdrptr)
            {
                // Code.
                if (filter->icmpopts.do_code && filter->icmpopts.code != icmphdrptr->code)
                {
                    continue;
                }

                // Type.
                if (filter->icmpopts.do_type && filter->icmpopts.type != icmphdrptr->type)
                {
                    continue;
                }  
            }
            else if (icmpv6hdrptr)
            {
                // Code.
                if (filter->icmpopts.do_code && filter->icmpopts.code != icmpv6hdrptr->icmp6_code)
                {
                    continue;
                }

                // Type.
                if (filter->icmpopts.do_type && filter->icmpopts.type != icmpv6hdrptr->icmp6_type)
                {
                    continue;
                }
            }
            else
            {
                continue;
            }
        }
        
#ifdef DEBUG
        printk("Matched rule ID #%d.\n", filter->id);
#endif
        
        action = filter->action;
        blocktime = filter->blocktime;

        if (action == 0) {
            return NF_DROP;
        }
        else {
            printk("MATCHED TO A RULE BUT THE ACTION IS TO PASS IT");
            return NF_ACCEPT;
        }
    }

    printk("Not Matched to Any rule\n");
    return NF_ACCEPT;
}

static struct nf_hook_ops my_nfho = {
    .hook = firewall_fun,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};

int __init my_hook_init(void)
{
      return nf_register_net_hook(&init_net, &my_nfho);
}

void __exit my_hook_exit(void)
{
      nf_unregister_net_hook(&init_net, &my_nfho);
}

module_init(my_hook_init);
module_exit(my_hook_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Arthur Silverio");