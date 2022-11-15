#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/time.h>

static unsigned int my_nf_hookfn(void *priv,struct sk_buff *skb, const struct nf_hook_state *state) {
      printk("PARSING THE PACKET INSIDE THE KERNEL:\n");
      
      struct iphdr* iph = ip_hdr(skb);
      struct tcphdr* tcph = tcp_hdr(skb);

      uint16_t sport = ntohs(tcph->source);
      uint16_t dport = ntohs(tcph->dest);

      printk("The source IP address is %pI4 | The destination IP address is %pI4\n", &iph->saddr, &iph->daddr);
      printk("The source port is %u | The destination port is %u\n", sport, dport);

      return NF_ACCEPT;
}

static struct nf_hook_ops my_nfho = {
      .hook        = my_nf_hookfn,
      .hooknum     = NF_INET_PRE_ROUTING,
      .pf          = PF_INET,
      .priority    = NF_IP_PRI_FIRST
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
