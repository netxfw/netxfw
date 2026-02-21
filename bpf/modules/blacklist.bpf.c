// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
#ifndef __NETXFW_BLACKLIST_BPF_C
#define __NETXFW_BLACKLIST_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"

/**
 * Helper to get lock/blacklist stats for an IP address (IPv4-mapped or IPv6)
 * 检查 IP 地址是否在黑名单中（包括危机、动态和静态）
 * 
 * Priority order (highest to lowest):
 * 优先级顺序（从高到低）：
 * 1. critical_blacklist - Emergency blocks, never auto-evict
 *    critical_blacklist - 紧急封锁，永不自动淘汰
 * 2. dynamic_blacklist - Auto-blocked IPs, auto-expiry
 *    dynamic_blacklist - 自动阻止的 IP，自动过期
 * 3. static_blacklist - Manual/CIDR blocks, persistent
 *    static_blacklist - 手动/CIDR 封锁，持久化
 */
static __always_inline struct rule_value *get_blacklist_stats(struct in6_addr *ip) {
    // 1. Check critical blacklist first - highest priority, never auto-evict
    // 优先检查危机黑名单 - 最高优先级，永不自动淘汰
    struct rule_value *val = bpf_map_lookup_elem(&critical_blacklist, ip);
    if (unlikely(val)) return val;

    // 2. Check dynamic blacklist (LRU) - optimized for frequent changes
    // 检查动态黑名单 (LRU)，针对高频变化的攻击 IP 优化
    val = bpf_map_lookup_elem(&dynamic_blacklist, ip);
    // Usually traffic is not blacklisted, so val is NULL most of the time
    // 通常流量不在黑名单中，所以 val 大多数时候为 NULL
    if (unlikely(val)) return val;

    // 3. Fallback to static blacklist (LPM) - for CIDR or manual blocks
    // 回退到静态黑名单 (LPM)，用于网段封禁或手动配置
    // Always use max prefix length for lookup in LPM map
    // 在 LPM 映射中始终使用最大前缀长度进行查找
    struct lpm_key key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    return bpf_map_lookup_elem(&static_blacklist, &key);
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
    bpf_map_update_elem(&dynamic_blacklist, ip, &block_val, BPF_ANY);
}

#endif // __NETXFW_BLACKLIST_BPF_C
