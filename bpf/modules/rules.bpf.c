// SPDX-License-Identifier: MIT
#ifndef __NETXFW_RULES_BPF_C
#define __NETXFW_RULES_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"

/**
 * Check if IP is in whitelist
 * IP is IPv4-mapped or IPv6
 */
static __always_inline int is_whitelisted(struct in6_addr *ip, __u16 port) {
    // Lookup in LPM trie using max prefix length
    struct lpm_key key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    
    struct rule_value *val = bpf_map_lookup_elem(&whitelist, &key);
    if (!val) return 0;
    
    // If counter > 1, it's a specific port allowance (legacy/future feature?)
    // Standard whitelist usually allows all ports (counter=0 or 1?)
    // Based on original code: if (val->counter > 1 && val->counter != port) return 0;
    // Assuming counter holds port if > 1.
    if (val->counter > 1 && val->counter != port) return 0;
    
    return 1;
}

/**
 * Check IP+Port specific rules
 */
static __always_inline int check_ip_port_rule(struct in6_addr *ip, __u16 port) {
    // Key structure: port (16) + pad (16) + ip (128)
    // Total bits = 160
    struct lpm_ip_port_key key = {
        .prefixlen = 160,
        .port = port,
        .pad = 0,
    };
    __builtin_memcpy(&key.ip, ip, sizeof(struct in6_addr));
    
    struct rule_value *val = bpf_map_lookup_elem(&ip_port_rules, &key);
    return val ? (__u8)val->counter : 0;
}

#endif // __NETXFW_RULES_BPF_C
