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
#include <linux/time.h>

#define MAX_PCKT_LENGTH 65535
#define MAX_FILTERS 100
#define MAX_TRACK_IPS 100000
#define MAX_CPUS 256

#define __u128 __uint128_t
#define _DEBUG

static unsigned int my_nf_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
      printk("PARSING THE PACKET INSIDE THE KERNEL:\n");

      struct iphdr *iph = ip_hdr(skb);
      struct tcphdr *tcph = tcp_hdr(skb);

      uint16_t sport = ntohs(tcph->source);
      uint16_t dport = ntohs(tcph->dest);

      printk("The source IP address is %pI4 | The destination IP address is %pI4\n", &iph->saddr, &iph->daddr);
      printk("The source port is %u | The destination port is %u\n", sport, dport);

      return NF_ACCEPT;
}

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

static unsigned int firewall_fun(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
      __u8 verlen;
      __u16 proto;
      __u32 nhoff = ETH_HLEN;
      __u128 srcip6 = 0;
      __u64 pps = 0;
      __u64 bps = 0;
      __u8 action = 0;
      __u64 blocktime = 1;
      int IP_HLEN;

      struct ethhdr* ethdr = {0};
      struct iphdr* iphdr = {0};
      struct ipv6hdr* ipv6hdr = {0};
      struct tcphdr* tcphdr = {0};
      struct udphdr* udphdr = {0};
      struct icmphdr* icmphdr = {0};
      struct icmp6hdr* icmp6hdr = {0};

      __u8 is_ipv4 = 0;
      __u8 is_ipv6 = 0;
      __u8 is_tcp = 0;
      __u8 is_udp = 0;
      __u8 is_icmp = 0;
      __u8 is_icmpv6 = 0;

      ethdr = eth_hdr(skb);
      if (ethdr->h_proto == htons(ETH_P_IPV6))
      {
            ipv6hdr = ipv6_hdr(skb);
            __builtin_memcpy(&srcip6, &ipv6hdr->saddr.in6_u.u6_addr32, sizeof(srcip6));
            is_ipv6 = 1;
            switch (ipv6hdr->nexthdr)
            {
            case IPPROTO_TCP:
                  is_tcp = 1;
                  tcphdr = tcp_hdr(skb);
                  break;
            case IPPROTO_UDP:
                  is_udp = 1;
                  udphdr = udp_hdr(skb);
                  break;
            case IPPROTO_ICMPV6:
                  is_icmpv6 = 1;
                  icmp6hdr = icmp6_hdr(skb);
                  break;
            default:
                  return NF_DROP;
            }
      }
      else if (ethdr->h_proto == htons(ETH_P_IP))
      {
            iphdr = ip_hdr(skb);
            is_ipv4 = 1;
            switch (iphdr->protocol)
            {
            case IPPROTO_TCP:
                  is_tcp = 1;
                  tcphdr = tcp_hdr(skb);
                  break;
            case IPPROTO_UDP:
                  is_udp = 1;
                  udphdr = udp_hdr(skb);
                  break;
            case IPPROTO_ICMPV6:
                  is_icmp = 1;
                  icmphdr = icmp_hdr(skb);
                  break;
            default:
                  return NF_DROP;
            }
      }
      else
      {
            return NF_DROP;
      }

      __u32 key = 0;
      ktime_t now = ktime_get();
      __u64 *blocked = NULL;

      for (__u8 i = 0; i < MAX_FILTERS; i++)
      {
            __u32 key = i;
            struct filter *filter;

            // Check if ID is above 0 (if 0, it's an invalid rule).
            if (!filter || filter->id < 1)
            {
                  break;
            }

#ifdef _DEBUG
            printk("Testing rule ID #%d.\n", filter->id);
#endif

            // Check if the rule is enabled.
            if (!filter->enabled)
            {
                  continue;
            }

            // Do specific IPv6.
            if (is_ipv6)
            {
                  // Source address.
                  if (filter->srcip6[0] &&
                      (ipv6hdr->saddr.in6_u.u6_addr32[0] != filter->srcip6[0] ||
                       ipv6hdr->saddr.in6_u.u6_addr32[1] != filter->srcip6[1] ||
                       ipv6hdr->saddr.in6_u.u6_addr32[2] != filter->srcip6[2] ||
                       ipv6hdr->saddr.in6_u.u6_addr32[3] != filter->srcip6[3]))
                  {
                        continue;
                  }

                  // Destination address.
                  if (filter->dstip6[0] &&
                      (ipv6hdr->daddr.in6_u.u6_addr32[0] != filter->dstip6[0] ||
                       ipv6hdr->daddr.in6_u.u6_addr32[1] != filter->dstip6[1] ||
                       ipv6hdr->daddr.in6_u.u6_addr32[2] != filter->dstip6[2] ||
                       ipv6hdr->daddr.in6_u.u6_addr32[3] != filter->dstip6[3]))
                  {
                        continue;
                  }

                  // Max TTL length.
                  if ((filter->do_max_ttl == 1) && (filter->max_ttl > ipv6hdr->hop_limit))
                  {
                        continue;
                  }

                  // Min TTL length.
                  if ((filter->do_min_ttl == 1) && (filter->min_ttl < ipv6hdr->hop_limit))
                  {
                        continue;
                  }

                  // Max packet length.
                  if ((filter->do_max_len == 1) && (filter->max_len > (ntohs(ipv6hdr->payload_len) + sizeof(struct ethhdr))))
                  {
                        continue;
                  }

                  // Min packet length.
                  if ((filter->do_min_len == 1) && (filter->min_len < (ntohs(ipv6hdr->payload_len) + sizeof(struct ethhdr))))
                  {
                        continue;
                  }
            }
            else if (is_ipv4)
            {
                  // Source address.
                  if (filter->srcip && ntohl(iphdr->saddr) == filter->srcip)
                  {
                        continue;
                  }

                  // Destination address.
                  if (filter->dstip && ntohl(iphdr->daddr) == filter->dstip)
                  {
                        continue;
                  }

                  // TOS.
                  if (filter->do_tos && filter->tos != iphdr->tos)
                  {
                        continue;
                  }

                  // Max TTL length.
                  if (filter->do_max_ttl && filter->max_ttl < iphdr->ttl)
                  {
                        continue;
                  }

                  // Min TTL length.
                  if (filter->do_min_ttl && filter->min_ttl > iphdr->ttl)
                  {
                        continue;
                  }

                  // Max packet length.
                  if (filter->do_max_len && filter->max_len < (ntohs(iphdr->tot_len) + sizeof(struct ethhdr)))
                  {
                        continue;
                  }

                  // Min packet length.
                  if (filter->do_min_len && filter->min_len > (ntohs(iphdr->tot_len) + sizeof(struct ethhdr)))
                  {
                        continue;
                  }
            }

            // Do TCP options.
            if (filter->tcpopts.enabled)
            {
                  if (!is_tcp)
                  {
                        continue;
                  }

                  // Source port.
                  if (filter->tcpopts.do_sport && htons(filter->tcpopts.sport) != tcphdr->source)
                  {
                        continue;
                  }

                  // Destination port.
                  if (filter->tcpopts.do_dport && htons(filter->tcpopts.dport) != tcphdr->dest)
                  {
                        continue;
                  }

                  // URG flag.
                  if (filter->tcpopts.do_urg && filter->tcpopts.urg != tcphdr->urg)
                  {
                        continue;
                  }

                  // ACK flag.
                  if (filter->tcpopts.do_ack && filter->tcpopts.ack != tcphdr->ack)
                  {
                        continue;
                  }

                  // RST flag.
                  if (filter->tcpopts.do_rst && filter->tcpopts.rst != tcphdr->rst)
                  {
                        continue;
                  }

                  // PSH flag.
                  if (filter->tcpopts.do_psh && filter->tcpopts.psh != tcphdr->psh)
                  {
                        continue;
                  }

                  // SYN flag.
                  if (filter->tcpopts.do_syn && filter->tcpopts.syn != tcphdr->syn)
                  {
                        continue;
                  }

                  // FIN flag.
                  if (filter->tcpopts.do_fin && filter->tcpopts.fin != tcphdr->fin)
                  {
                        continue;
                  }

                  // ECE flag.
                  if (filter->tcpopts.do_ece && filter->tcpopts.ece != tcphdr->ece)
                  {
                        continue;
                  }

                  // CWR flag.
                  if (filter->tcpopts.do_cwr && filter->tcpopts.cwr != tcphdr->cwr)
                  {
                        continue;
                  }
            }
            else if (filter->udpopts.enabled)
            {
                  if (!is_udp)
                  {
                        continue;
                  }

                  // Source port.
                  if (filter->udpopts.do_sport && htons(filter->udpopts.sport) != udphdr->source)
                  {
                        continue;
                  }

                  // Destination port.
                  if (filter->udpopts.do_dport && htons(filter->udpopts.dport) != udphdr->dest)
                  {

                        continue;
                  }
            }
            else if (filter->icmpopts.enabled)
            {
                  if (is_icmp)
                  {
                        // Code.
                        if (filter->icmpopts.do_code && filter->icmpopts.code != icmphdr->code)
                        {
                              continue;
                        }

                        // Type.
                        if (filter->icmpopts.do_type && filter->icmpopts.type != icmphdr->type)
                        {
                              continue;
                        }
                  }
                  else if (is_icmpv6)
                  {
                        // Code.
                        if (filter->icmpopts.do_code && filter->icmpopts.code != icmp6hdr->icmp6_code)
                        {
                              continue;
                        }

                        // Type.
                        if (filter->icmpopts.do_type && filter->icmpopts.type != icmp6hdr->icmp6_type)
                        {
                              continue;
                        }
                  }
                  else
                  {
                        continue;
                  }
            }
#ifdef _DEBUG
            printk("Matched rule ID #%d.\n", filter->id);
#endif

            action = filter->action;
            blocktime = filter->blocktime;

            goto matched;
      }

notmatched:
#ifdef _DEBUG
      printk("NO MATCH TO ANY RULE\n");
#endif

      /* Do something */
      return NF_ACCEPT;

matched:
      if (action == 0)
      {
#ifdef _DEBUG
            printk("MATCHED TO A RULE: DROPPING\n");
#endif
            if (blocktime > 0)
            {
                  __u64 newTime = now + (blocktime * 1000000000);
            }
            return NF_DROP;
      }
      else
      {
#ifdef _DEBUG
            printk("MATCHED TO A RULE: BUT THE DROP IS DISABLED\n");
#endif
            goto notmatched;
            return NF_ACCEPT;
      }
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