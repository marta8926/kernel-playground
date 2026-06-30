#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// Funkcja dla IPv4
static unsigned int ttl_ipv4_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    if (iph) {
        pr_info("M14 IPv4 Packet - TTL: %u\n", iph->ttl);
    }
    return NF_ACCEPT;
}

// Funkcja dla IPv6
static unsigned int hop_limit_ipv6_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    if (ip6h) {
        pr_info("M14 IPv6 Packet - Hop Limit: %u\n", ip6h->hop_limit);
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_ipv4 = {
    .hook = ttl_ipv4_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_ipv6 = {
    .hook = hop_limit_ipv6_hook,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP6_PRI_FIRST,
};

static int __init m14_init(void) {
    nf_register_net_hook(&init_net, &nfho_ipv4);
    nf_register_net_hook(&init_net, &nfho_ipv6);
    pr_info("m14_ttl: loaded\n");
    return 0;
}

static void __exit m14_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho_ipv4);
    nf_unregister_net_hook(&init_net, &nfho_ipv6);
    pr_info("m14_ttl: unloaded\n");
}

module_init(m14_init);
module_exit(m14_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marta");
MODULE_DESCRIPTION("M14 TTL Inspector");
