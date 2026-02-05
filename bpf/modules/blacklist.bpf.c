// SPDX-License-Identifier: MIT
#ifndef __NETXFW_BLACKLIST_BPF_C
#define __NETXFW_BLACKLIST_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"

/**
 * Helper to get lock/blacklist stats for an IPv4 address
 * 检查 IPv4 地址是否在黑名单中（包括动态和静态）
 */
static __always_inline struct rule_value *get_blacklist_stats(__u32 ip) {
    // 1. Check dynamic blacklist (LRU) first - optimized for frequent changes
    // 优先检查动态黑名单 (LRU)，针对高频变化的攻击 IP 优化
    struct rule_value *val = bpf_map_lookup_elem(&dyn_lock_list, &ip);
    if (val) return val;

    // 2. Fallback to static lock list (LPM) - for CIDR or manual blocks
    // 回退到静态黑名单 (LPM)，用于网段封禁或手动配置
    struct lpm_key4 key = { .prefixlen = 32, .data = ip };
    return bpf_map_lookup_elem(&lock_list, &key);
}

/**
 * Helper to add an IPv4 to the dynamic blacklist
 * 将 IPv4 地址加入动态黑名单
 */
static __always_inline void add_to_blacklist(__u32 ip) {
    if (!cached_auto_block) return;

    __u64 now = bpf_ktime_get_ns();
    struct rule_value block_val = {
        .counter = 0,
        .expires_at = (cached_auto_block_expiry > 0) ? (now + (cached_auto_block_expiry * 1000000000ULL)) : 0
    };
    bpf_map_update_elem(&dyn_lock_list, &ip, &block_val, BPF_ANY);
}

#ifdef ENABLE_IPV6
/**
 * Helper to get lock/blacklist stats for an IPv6 address
 * 检查 IPv6 地址是否在黑名单中
 */
static __always_inline struct rule_value *get_blacklist_stats6(struct in6_addr *ip) {
    // 1. Check dynamic blacklist (LRU) first
    struct rule_value *val = bpf_map_lookup_elem(&dyn_lock_list6, ip);
    if (val) return val;

    // 2. Fallback to static lock list (LPM)
    struct lpm_key6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    return bpf_map_lookup_elem(&lock_list6, &key);
}

/**
 * Helper to add an IPv6 to the dynamic blacklist
 * 将 IPv6 地址加入动态黑名单
 */
static __always_inline void add_to_blacklist6(struct in6_addr *ip) {
    if (!cached_auto_block) return;

    __u64 now = bpf_ktime_get_ns();
    struct rule_value block_val = {
        .counter = 0,
        .expires_at = (cached_auto_block_expiry > 0) ? (now + (cached_auto_block_expiry * 1000000000ULL)) : 0
    };
    bpf_map_update_elem(&dyn_lock_list6, ip, &block_val, BPF_ANY);
}
#endif

#endif // __NETXFW_BLACKLIST_BPF_C
