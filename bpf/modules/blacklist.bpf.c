// SPDX-License-Identifier: MIT
#ifndef __NETXFW_BLACKLIST_BPF_C
#define __NETXFW_BLACKLIST_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"

/**
 * Helper to get lock/blacklist stats for an IP address (IPv4-mapped or IPv6)
 * 检查 IP 地址是否在黑名单中（包括动态和静态）
 */
static __always_inline struct rule_value *get_blacklist_stats(struct in6_addr *ip) {
    // 1. Check dynamic blacklist (LRU) first - optimized for frequent changes
    // 优先检查动态黑名单 (LRU)，针对高频变化的攻击 IP 优化
    struct rule_value *val = bpf_map_lookup_elem(&dyn_lock_list, ip);
    // Usually traffic is not blacklisted, so val is NULL most of the time
    // 通常流量不在黑名单中，所以 val 大多数时候为 NULL
    if (unlikely(val)) return val;

    // 2. Fallback to static lock list (LPM) - for CIDR or manual blocks
    // 回退到静态黑名单 (LPM)，用于网段封禁或手动配置
    // Always use max prefix length for lookup in LPM map
    // 在 LPM 映射中始终使用最大前缀长度进行查找
    struct lpm_key key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    return bpf_map_lookup_elem(&lock_list, &key);
}

/**
 * Helper to add an IP to the dynamic blacklist
 * 将 IP 地址加入动态黑名单
 */
static __always_inline void add_to_blacklist(struct in6_addr *ip) {
    if (!cached_auto_block) return;

    __u64 now = bpf_ktime_get_ns();
    struct rule_value block_val = {
        .counter = 0,
        .expires_at = (cached_auto_block_expiry > 0) ? (now + (cached_auto_block_expiry * 1000000000ULL)) : 0
    };
    bpf_map_update_elem(&dyn_lock_list, ip, &block_val, BPF_ANY);
}

#endif // __NETXFW_BLACKLIST_BPF_C
