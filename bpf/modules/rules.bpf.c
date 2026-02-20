// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __NETXFW_RULES_BPF_C
#define __NETXFW_RULES_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"

/**
 * Check if IP is in whitelist
 * IP is IPv4-mapped or IPv6
 * 检查 IP 是否在白名单中
 * IP 是 IPv4 映射或 IPv6
 */
static __always_inline int is_whitelisted(struct in6_addr *ip, __u16 port) {
    // Lookup in LPM trie using max prefix length
    // 使用最大前缀长度在 LPM Trie 中查找
    struct lpm_key key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    
    struct rule_value *val = bpf_map_lookup_elem(&whitelist, &key);
    if (!val) return 0;
    
    // If counter > 1, it's a specific port allowance (legacy/future feature?)
    // Standard whitelist usually allows all ports (counter=0 or 1?)
    // Based on original code: if (val->counter > 1 && val->counter != port) return 0;
    // Assuming counter holds port if > 1.
    // 如果计数器 > 1，则为特定端口允许（旧版/未来功能？）
    // 标准白名单通常允许所有端口（计数器=0 或 1？）
    // 基于原始代码：if (val->counter > 1 && val->counter != port) return 0;
    // 假设如果 > 1，计数器保存端口。
    if (val->counter > 1 && val->counter != port) return 0;
    
    return 1;
}

/**
 * Check IP+Port specific rules
 * 检查 IP+端口特定规则
 */
static __always_inline int check_ip_port_rule(struct in6_addr *ip, __u16 port) {
    // Key structure: port (16) + pad (16) + ip (128)
    // Total bits = 160
    // 键结构：端口 (16) + 填充 (16) + IP (128)
    // 总位数 = 160
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
