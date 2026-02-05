// SPDX-License-Identifier: MIT
#ifndef __NETXFW_RULES_BPF_C
#define __NETXFW_RULES_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"

static __always_inline int is_whitelisted(__u32 ip, __u16 port) {
    struct lpm_key4 key = {
        .prefixlen = 32,
        .data = ip,
    };
    struct rule_value *val = bpf_map_lookup_elem(&whitelist, &key);
    if (!val) return 0;
    if (val->counter > 1 && val->counter != port) return 0;
    return 1;
}

#ifdef ENABLE_IPV6
static __always_inline int is_whitelisted6(struct in6_addr *ip, __u16 port) {
    struct lpm_key6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&whitelist6, &key);
    if (!val) return 0;
    if (val->counter > 1 && val->counter != port) return 0;
    return 1;
}
#endif

static __always_inline int check_ip_port_rule(__u32 ip, __u16 port) {
    struct lpm_ip4_port_key key = {
        .prefixlen = 64,
        .port = port,
        .pad = 0,
        .ip = ip,
    };
    struct rule_value *val = bpf_map_lookup_elem(&ip_port_rules, &key);
    return val ? (__u8)val->counter : 0;
}

#ifdef ENABLE_IPV6
static __always_inline int check_ip6_port_rule(struct in6_addr *ip, __u16 port) {
    struct lpm_ip6_port_key key = {
        .prefixlen = 160,
        .port = port,
        .pad = 0,
    };
    __builtin_memcpy(&key.ip, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&ip_port_rules6, &key);
    return val ? (__u8)val->counter : 0;
}
#endif

static __always_inline struct rule_value *get_lock_stats(__u32 ip) {
    // 1. Check dynamic blacklist (LRU) first
    struct rule_value *val = bpf_map_lookup_elem(&dyn_lock_list, &ip);
    if (val) return val;

    // 2. Fallback to static lock list (LPM)
    struct lpm_key4 key = { .prefixlen = 32, .data = ip };
    return bpf_map_lookup_elem(&lock_list, &key);
}

#ifdef ENABLE_IPV6
static __always_inline struct rule_value *get_lock_stats6(struct in6_addr *ip) {
    // 1. Check dynamic blacklist (LRU) first
    struct rule_value *val = bpf_map_lookup_elem(&dyn_lock_list6, ip);
    if (val) return val;

    // 2. Fallback to static lock list (LPM)
    struct lpm_key6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    return bpf_map_lookup_elem(&lock_list6, &key);
}
#endif

#endif // __NETXFW_RULES_BPF_C
