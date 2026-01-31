// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/**
 * LPM (Longest Prefix Match) structures for CIDR matching
 * LPM (最长前缀匹配) 结构体，用于 CIDR 网段匹配
 */
struct lpm_key4 {
    __u32 prefixlen;
    __u32 data;
};

struct lpm_key6 {
    __u32 prefixlen;
    struct in6_addr data;
};

/**
 * IP+Port LPM structures
 * IP+端口 LPM 结构体
 */
struct lpm_ip4_port_key {
    __u32 prefixlen;
    __u16 port;
    __u16 pad;
    __u32 ip;
};

struct lpm_ip6_port_key {
    __u32 prefixlen;
    __u16 port;
    __u16 pad;
    struct in6_addr ip;
};

/**
 * Map values with expiration support
 * 带有过期支持的 Map 值结构体
 */
struct rule_value {
    __u64 counter;    // Counter or action / 计数器或动作
    __u64 expires_at; // Expiration timestamp (nanoseconds) / 过期时间戳（纳秒）
};

/**
 * Lock maps: store locked IPv4/IPv6 ranges and their drop counts
 * 锁定 Map：存储封禁的 IPv4/IPv6 网段及其拦截计数
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key4);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key6);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list6 SEC(".maps");

/**
 * Global drop statistics
 * 全局拦截统计次数
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

/**
 * Whitelist maps: store allowed IPv4/IPv6 ranges
 * 白名单 Map：存储允许通过的 IPv4/IPv6 网段
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key4);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key6);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist6 SEC(".maps");

/**
 * Port allow list: store allowed ports (TCP/UDP)
 * 端口白名单：存储允许的端口 (TCP/UDP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct rule_value);
} allowed_ports SEC(".maps");

/**
 * IP+Port rule maps: store allow/deny for specific IP+Port combinations
 * IP+端口规则 Map：存储特定 IP+端口组合的允许/拒绝规则
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_ip4_port_key);
    __type(value, struct rule_value); // counter field as: 1: allow, 2: deny
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_port_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_ip6_port_key);
    __type(value, struct rule_value); // counter field as: 1: allow, 2: deny
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_port_rules6 SEC(".maps");

/**
 * Global configuration: flags like DEFAULT_DENY
 * 全局配置：存储如 DEFAULT_DENY 等标志
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} global_config SEC(".maps");

#define CONFIG_DEFAULT_DENY 0

/**
 * Helper to check if a rule is expired
 * 检查规则是否已过期
 */
static inline int is_expired(struct rule_value *val) {
    if (!val || val->expires_at == 0) {
        return 0; // No expiration / 未设置过期时间
    }
    __u64 now = bpf_ktime_get_ns();
    if (now > val->expires_at) {
        return 1; // Expired / 已过期
    }
    return 0;
}

/**
 * Helper to check if an IPv4 address is whitelisted
 * 检查 IPv4 地址是否在白名单中
 */
static inline int is_whitelisted(__u32 ip) {
    struct lpm_key4 key = {
        .prefixlen = 32,
        .data = ip,
    };
    struct rule_value *val = bpf_map_lookup_elem(&whitelist, &key);
    if (!val) return 0;
    if (is_expired(val)) return 0;
    return 1;
}

/**
 * Helper to check if an IPv6 address is whitelisted
 * 检查 IPv6 地址是否在白名单中
 */
static inline int is_whitelisted6(struct in6_addr *ip) {
    struct lpm_key6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&whitelist6, &key);
    if (!val) return 0;
    if (is_expired(val)) return 0;
    return 1;
}

/**
 * Helper to check IP+Port rules for IPv4
 * 检查 IPv4 的 IP+端口规则
 * Returns: 0 (no rule), 1 (allow), 2 (deny)
 */
static inline int check_ip_port_rule(__u32 ip, __u16 port) {
    struct lpm_ip4_port_key key = {
        .prefixlen = 64, // 16 bits port + 16 bits pad + 32 bits ip
        .port = port,
        .pad = 0,
        .ip = ip,
    };
    struct rule_value *val = bpf_map_lookup_elem(&ip_port_rules, &key);
    if (val) {
        if (is_expired(val)) return 0;
        return (__u8)val->counter;
    }
    return 0;
}

/**
 * Helper to check IP+Port rules for IPv6
 * 检查 IPv6 的 IP+端口规则
 * Returns: 0 (no rule), 1 (allow), 2 (deny)
 */
static inline int check_ip6_port_rule(struct in6_addr *ip, __u16 port) {
    struct lpm_ip6_port_key key = {
        .prefixlen = 160, // 16 bits port + 16 bits pad + 128 bits ip
        .port = port,
        .pad = 0,
    };
    __builtin_memcpy(&key.ip, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&ip_port_rules6, &key);
    if (val) {
        if (is_expired(val)) return 0;
        return (__u8)val->counter;
    }
    return 0;
}

/**
 * Helper to get lock stats for an IPv4 address (checks if locked)
 * 获取 IPv4 地址的锁定统计（同时检查是否被锁定）
 */
static inline struct rule_value *get_lock_stats(__u32 ip) {
    struct lpm_key4 key = {
        .prefixlen = 32,
        .data = ip,
    };
    struct rule_value *val = bpf_map_lookup_elem(&lock_list, &key);
    if (val && is_expired(val)) return NULL;
    return val;
}

/**
 * Helper to get lock stats for an IPv6 address (checks if locked)
 * 获取 IPv6 地址的锁定统计（同时检查是否被锁定）
 */
static inline struct rule_value *get_lock_stats6(struct in6_addr *ip) {
    struct lpm_key6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&lock_list6, &key);
    if (val && is_expired(val)) return NULL;
    return val;
}

/**
 * Main XDP firewall program
 * XDP 防火墙主程序
 */
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header check / 以太网头部检查
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    // Handle IPv4 / 处理 IPv4
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        // 1. Check global whitelist / 首先检查全局白名单
        if (is_whitelisted(ip->saddr)) {
            return XDP_PASS;
        }

        // 2. Check global lock list / 检查全局锁定列表
        struct rule_value *cnt = get_lock_stats(ip->saddr);
        if (cnt) {
            __sync_fetch_and_add(&cnt->counter, 1);
            goto drop_packet;
        }

        // 3. Extract port and check IP+Port rules / 提取端口并检查 IP+端口规则
        __u16 dest_port = 0;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                dest_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + sizeof(*ip);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                dest_port = bpf_ntohs(udp->dest);
            }
        }

        if (dest_port > 0) {
            // Check IP+Port rules (Port-first LPM matching) / 检查 IP+端口规则（端口优先的 LPM 匹配）
            int rule_action = check_ip_port_rule(ip->saddr, dest_port);
            if (rule_action == 1) return XDP_PASS; // Allow / 允许
            if (rule_action == 2) goto drop_packet; // Deny / 拒绝
        }

        // 4. Check Default Deny and Port Allow List / 检查默认拒绝和端口白名单
        __u32 config_key = CONFIG_DEFAULT_DENY;
        __u32 *default_deny = bpf_map_lookup_elem(&global_config, &config_key);

        if (dest_port > 0) {
            // Then check global allowed ports if default deny is on / 如果开启了默认拒绝，再检查全局允许端口
            if (default_deny && *default_deny == 1) {
                struct rule_value *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dest_port);
                if (port_allowed && !is_expired(port_allowed)) {
                    return XDP_PASS;
                }
                goto drop_packet;
            }
        }
    }
    // Handle IPv6 / 处理 IPv6
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
            return XDP_PASS;

        // 1. Check global whitelist / 首先检查全局白名单
        if (is_whitelisted6(&ip6->saddr)) {
            return XDP_PASS;
        }

        // 2. Check global lock list / 检查全局锁定列表
        struct rule_value *cnt = get_lock_stats6(&ip6->saddr);
        if (cnt) {
            __sync_fetch_and_add(&cnt->counter, 1);
            goto drop_packet;
        }

        // 3. Extract port and check IP+Port rules / 提取端口并检查 IP+端口规则
        __u16 dest_port = 0;
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                dest_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip6 + sizeof(*ip6);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                dest_port = bpf_ntohs(udp->dest);
            }
        }

        if (dest_port > 0) {
            // Check IP+Port rules (Port-first LPM matching) / 检查 IP+端口规则（端口优先的 LPM 匹配）
            int rule_action = check_ip6_port_rule(&ip6->saddr, dest_port);
            if (rule_action == 1) return XDP_PASS; // Allow / 允许
            if (rule_action == 2) goto drop_packet; // Deny / 拒绝
        }

        // 4. Check Default Deny and Port Allow List / 检查默认拒绝和端口白名单
        __u32 config_key = CONFIG_DEFAULT_DENY;
        __u32 *default_deny = bpf_map_lookup_elem(&global_config, &config_key);

        if (dest_port > 0) {
            // Then check global allowed ports if default deny is on / 如果开启了默认拒绝，再检查全局允许端口
            if (default_deny && *default_deny == 1) {
                struct rule_value *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dest_port);
                if (port_allowed && !is_expired(port_allowed)) {
                    return XDP_PASS;
                }
                goto drop_packet;
            }
        }
    }

    return XDP_PASS;

drop_packet:
    // Increment global drop counter / 增加全局拦截计数
    {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
        if (count) {
            *count += 1;
        }
    }
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual MIT/GPL";
