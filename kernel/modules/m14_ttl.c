/*
 * Project: M14 - Packet TTL Inspection (Netfilter)
 * Author: Marta Rolbiecka [0383386]
 * Course: Software Networks (2025-2026)
 * Description: A Netfilter kernel module that intercepts incoming 
 * IPv4 and IPv6 traffic to log Time-To-Live (TTL) and Hop Limit values.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

/* * IPv4 Hook Function
 * Extracts the IPv4 header and logs the TTL value.
 */
static unsigned int ttl_ipv4_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    
    // Safety check: ensure the IP header exists before accessing it
    if (iph) {
        pr_info("M14 IPv4 Packet - TTL: %u\n", iph->ttl);
    }
    
    // Allow the packet to continue through the network stack
    return NF_ACCEPT;
}

/* * IPv6 Hook Function
 * Extracts the IPv6 header and logs the Hop Limit value.
 */
static unsigned int hop_limit_ipv6_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    
    // Safety check: ensure the IPv6 header exists before accessing it
    if (ip6h) {
        pr_info("M14 IPv6 Packet - Hop Limit: %u\n", ip6h->hop_limit);
    }
    
    // Allow the packet to continue through the network stack
    return NF_ACCEPT;
}

// Netfilter hook configuration for IPv4
static struct nf_hook_ops nfho_ipv4 = {
    .hook = ttl_ipv4_hook,               // Callback function for IPv4
    .pf = NFPROTO_IPV4,                  // Target IPv4 protocol family
    .hooknum = NF_INET_PRE_ROUTING,      // Intercept packets before routing decisions
    .priority = NF_IP_PRI_FIRST,         // Execute with the highest priority
};

// Netfilter hook configuration for IPv6
static struct nf_hook_ops nfho_ipv6 = {
    .hook = hop_limit_ipv6_hook,         // Callback function for IPv6
    .pf = NFPROTO_IPV6,                  // Target IPv6 protocol family
    .hooknum = NF_INET_PRE_ROUTING,      // Intercept packets before routing decisions
    .priority = NF_IP6_PRI_FIRST,        // Execute with the highest priority
};

/* * Module Initialization
 * Registers both Netfilter hooks (IPv4 and IPv6) with the kernel.
 */
static int __init m14_init(void) {
    nf_register_net_hook(&init_net, &nfho_ipv4);
    nf_register_net_hook(&init_net, &nfho_ipv6);
    pr_info("m14_ttl: loaded\n");
    
    return 0;
}

/* * Module Cleanup
 * Unregisters the Netfilter hooks before the module is unloaded.
 */
static void __exit m14_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho_ipv4);
    nf_unregister_net_hook(&init_net, &nfho_ipv6);
    pr_info("m14_ttl: unloaded\n");
}

// Register module entry and exit points
module_init(m14_init);
module_exit(m14_exit);

// Module metadata required by the Linux kernel
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marta Rolbiecka");
MODULE_DESCRIPTION("M14 TTL and Hop Limit Inspector");
