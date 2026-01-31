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
#include <linux/pkt_cls.h>

/**
 * Conntrack (Connection Tracking) structures
 * 连接追踪结构体
 */
struct ct_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3]; // Explicit padding for alignment
} __attribute__((packed));

struct ct_key6 {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3]; // Explicit padding for alignment
} __attribute__((packed));

struct ct_value {
    __u64 last_seen;
};

/**
 * Conntrack map: stores active connections using LRU for auto-eviction
 * 连接追踪 Map：使用 LRU 存储活跃连接，支持自动驱逐
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct ct_key);
    __type(value, struct ct_value);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct ct_key6);
    __type(value, struct ct_value);
} conntrack_map6 SEC(".maps");

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
 * ICMP rate limiting structures
 * ICMP 限速结构体
 */
struct icmp_stats {
    __u64 last_time;
    __u64 tokens;
};

/**
 * Lock maps: store locked IPv4/IPv6 ranges and their drop counts
 * 锁定 Map：存储封禁的 IPv4/IPv6 网段及其拦截计数
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 2000000);
    __type(key, struct lpm_key4);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000000);
    __type(key, struct lpm_key6);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list6 SEC(".maps");

/**
 * Global statistics
 * 全局统计信息
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pass_stats SEC(".maps");

/**
 * ICMP rate limit state
 * ICMP 限速状态
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_stats);
} icmp_limit_map SEC(".maps");

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
 * Optimized: Use PERCPU_HASH for better performance
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
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
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64); // Use __u64 for all config values
} global_config SEC(".maps");

#define CONFIG_DEFAULT_DENY 0
#define CONFIG_ALLOW_RETURN_TRAFFIC 1
#define CONFIG_ALLOW_ICMP 2
#define CONFIG_ENABLE_CONNTRACK 3
#define CONFIG_CONNTRACK_TIMEOUT 4
#define CONFIG_ICMP_RATE 5
#define CONFIG_ICMP_BURST 6
#define CONFIG_CONFIG_VERSION 7

// BPF-side configuration cache
static __u64 cached_version = 0;
static __u32 cached_ct_enabled = 0;
static __u32 cached_allow_icmp = 0;
static __u32 cached_allow_return = 0;
static __u32 cached_default_deny = 0;
static __u64 cached_ct_timeout = 3600000000000ULL;
static __u64 cached_icmp_rate = 10;   // 10 packets/sec
static __u64 cached_icmp_burst = 50;  // 50 packets burst

static __always_inline void refresh_config() {
    __u32 key = CONFIG_CONFIG_VERSION;
    __u64 *ver = bpf_map_lookup_elem(&global_config, &key);
    if (ver && *ver != cached_version) {
        cached_version = *ver;

        __u64 *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ENABLE_CONNTRACK});
        if (val) cached_ct_enabled = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ALLOW_ICMP});
        if (val) cached_allow_icmp = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ALLOW_RETURN_TRAFFIC});
        if (val) cached_allow_return = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_DEFAULT_DENY});
        if (val) cached_default_deny = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_CONNTRACK_TIMEOUT});
        if (val) cached_ct_timeout = *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ICMP_RATE});
        if (val) cached_icmp_rate = *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ICMP_BURST});
        if (val) cached_icmp_burst = *val;
    }
}

/**
 * Helper to check if an IPv4 address is whitelisted
 * 检查 IPv4 地址是否在白名单中
 */
static inline int is_whitelisted(__u32 ip, __u16 port) {
    struct lpm_key4 key = {
        .prefixlen = 32,
        .data = ip,
    };
    struct rule_value *val = bpf_map_lookup_elem(&whitelist, &key);
    if (!val) return 0;

    // If counter is 0 or 1, it means all ports are allowed (legacy behavior)
    // If counter > 1, it specifies a specific allowed port
    // 如果 counter 为 0 或 1，表示允许所有端口（兼容旧行为）
    // 如果 counter > 1，表示仅允许特定的端口
    if (val->counter > 1 && val->counter != port) {
        return 0;
    }
    return 1;
}

/**
 * Helper to check if an IPv6 address is whitelisted
 * 检查 IPv6 地址是否在白名单中
 */
static inline int is_whitelisted6(struct in6_addr *ip, __u16 port) {
    struct lpm_key6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&whitelist6, &key);
    if (!val) return 0;

    if (val->counter > 1 && val->counter != port) {
        return 0;
    }
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
    return bpf_map_lookup_elem(&lock_list, &key);
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
    return bpf_map_lookup_elem(&lock_list6, &key);
}

/**
 * Helper to check ICMP rate limit using token bucket
 * 使用令牌桶检查 ICMP 限速
 */
static __always_inline int check_icmp_limit() {
    __u32 key = 0;
    struct icmp_stats *stats = bpf_map_lookup_elem(&icmp_limit_map, &key);
    if (!stats) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - stats->last_time;

    // Tokens to add: elapsed (ns) * rate (packets/sec) / 1e9 (ns/sec)
    // For precision and to avoid overflow, we do: (elapsed * rate) / 1,000,000,000
    __u64 tokens_to_add = (elapsed * cached_icmp_rate) / 1000000000ULL;

    __u64 new_tokens = stats->tokens + tokens_to_add;
    if (new_tokens > cached_icmp_burst) {
        new_tokens = cached_icmp_burst;
    }

    if (new_tokens >= 1) {
        stats->tokens = new_tokens - 1;
        stats->last_time = now;
        return 1; // Allow
    }

    return 0; // Drop
}

/**
 * Main XDP firewall program
 * XDP 防火墙主程序
 */
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ethernet header check / 以太网头部检查
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    // Refresh config from map if version changed
    refresh_config();

    // Use cached values
    __u32 ct_enabled = cached_ct_enabled;
    __u32 allow_icmp = cached_allow_icmp;
    __u32 allow_return = cached_allow_return;
    __u32 default_deny = cached_default_deny;
    __u64 ct_timeout = cached_ct_timeout;

    // Handle IPv4 / 处理 IPv4
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        // Extract port first to support port-specific whitelist
        // 首先提取端口，以支持特定端口的白名单校验
        __u16 src_port = 0;
        __u16 dest_port = 0;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dest_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + sizeof(*ip);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dest_port = bpf_ntohs(udp->dest);
            }
        }

        // 1. Check global whitelist (with port support) / 首先检查全局白名单（支持端口校验）
        if (is_whitelisted(ip->saddr, dest_port)) {
            goto pass_packet;
        }

        // 2. Check global lock list / 检查全局锁定列表
        struct rule_value *cnt = get_lock_stats(ip->saddr);
        if (cnt) {
            __sync_fetch_and_add(&cnt->counter, 1);
            goto drop_packet;
        }

        // 3. Check Conntrack (Stateful) / 检查连接追踪（有状态）
        if (ct_enabled == 1) {
            struct ct_key look_key = {
                .src_ip = ip->daddr,
                .dst_ip = ip->saddr,
                .src_port = dest_port,
                .dst_port = src_port,
                .protocol = ip->protocol,
            };
            struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &look_key);
            if (ct_val) {
                // Security check: dynamic timeout
                if (bpf_ktime_get_ns() - ct_val->last_seen < ct_timeout) {
                    goto pass_packet;
                }
            }
        }

        // 3. Check IP+Port rules
        if (dest_port > 0) {
            // Check IP+Port rules (Port-first LPM matching) / 检查 IP+端口规则（端口优先的 LPM 匹配）
            int rule_action = check_ip_port_rule(ip->saddr, dest_port);
            if (rule_action == 1) goto pass_packet; // Allow / 允许
            if (rule_action == 2) goto drop_packet; // Deny / 拒绝
        }

        // 3.4 Check for ICMP / 检查 ICMP 流量
        if (ip->protocol == IPPROTO_ICMP) {
            if (allow_icmp == 1) {
                // Optimized: Add rate limiting to ICMP
                if (check_icmp_limit()) {
                    goto pass_packet;
                }
                goto drop_packet;
            }
        }

        // 3.5 Check for return traffic / 检查回包流量
        if (allow_return == 1) {
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                if ((void *)tcp + sizeof(*tcp) <= data_end) {
                    // If it's an ACK packet and destination port is in ephemeral range
                    // 如果是 ACK 包且目标端口在临时端口范围内
                    if (tcp->ack && dest_port >= 32768) {
                        goto pass_packet;
                    }
                }
            } else if (ip->protocol == IPPROTO_UDP) {
                // For UDP, we can only check if destination port is in ephemeral range
                // 对 UDP 只能检查目标端口是否在临时端口范围内
                if (dest_port >= 32768) {
                    goto pass_packet;
                }
            }
        }

        // 4. Check Default Deny and Port Allow List / 检查默认拒绝和端口白名单
        if (dest_port > 0) {
            // Then check global allowed ports if default deny is on / 如果开启了默认拒绝，再检查全局允许端口
            if (default_deny == 1) {
                struct rule_value *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dest_port);
                if (port_allowed) {
                    goto pass_packet;
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

        // Extract port first
        __u16 src_port = 0;
        __u16 dest_port = 0;
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dest_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip6 + sizeof(*ip6);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dest_port = bpf_ntohs(udp->dest);
            }
        }

        // 1. Check global whitelist (with port support)
        if (is_whitelisted6(&ip6->saddr, dest_port)) {
            goto pass_packet;
        }

        // 2. Check global lock list
        struct rule_value *cnt = get_lock_stats6(&ip6->saddr);
        if (cnt) {
            __sync_fetch_and_add(&cnt->counter, 1);
            goto drop_packet;
        }

        // 3. Check Conntrack (Stateful) / 检查连接追踪（有状态）
        if (ct_enabled == 1) {
            struct ct_key6 look_key = {
                .src_ip = ip6->daddr,
                .dst_ip = ip6->saddr,
                .src_port = dest_port,
                .dst_port = src_port,
                .protocol = ip6->nexthdr,
            };
            struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map6, &look_key);
            if (ct_val) {
                // Security check: dynamic timeout
                if (bpf_ktime_get_ns() - ct_val->last_seen < ct_timeout) {
                    goto pass_packet;
                }
            }
        }

        // 3. Check IP+Port rules
        if (dest_port > 0) {
            // Check IP+Port rules (Port-first LPM matching) / 检查 IP+端口规则（端口优先的 LPM 匹配）
            int rule_action = check_ip6_port_rule(&ip6->saddr, dest_port);
            if (rule_action == 1) goto pass_packet; // Allow / 允许
            if (rule_action == 2) goto drop_packet; // Deny / 拒绝
        }

        // 3.4 Check for ICMPv6 / 检查 ICMPv6 流量
        if (ip6->nexthdr == IPPROTO_ICMPV6) {
            if (allow_icmp == 1) {
                // Optimized: Add rate limiting to ICMPv6
                if (check_icmp_limit()) {
                    goto pass_packet;
                }
                goto drop_packet;
            }
        }

        // 3.5 Check for return traffic / 检查回包流量
        if (allow_return == 1) {
            if (ip6->nexthdr == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
                if ((void *)tcp + sizeof(*tcp) <= data_end) {
                    if (tcp->ack && dest_port >= 32768) {
                        goto pass_packet;
                    }
                }
            } else if (ip6->nexthdr == IPPROTO_UDP) {
                if (dest_port >= 32768) {
                    goto pass_packet;
                }
            }
        }

        // 4. Check Default Deny and Port Allow List / 检查默认拒绝和端口白名单
        if (dest_port > 0) {
            // Then check global allowed ports if default deny is on / 如果开启了默认拒绝，再检查全局允许端口
            if (default_deny == 1) {
                struct rule_value *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dest_port);
                if (port_allowed) {
                    goto pass_packet;
                }
                goto drop_packet;
            }
        }
    }

    goto pass_packet;

pass_packet:
    // Increment global pass counter / 增加全局放行计数
    {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&pass_stats, &key);
        if (count) {
            *count += 1;
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

/**
 * TC Egress program for connection tracking
 * 用于连接追踪的 TC 出站程序
 */
SEC("classifier")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Check if conntrack is enabled
    __u32 key = CONFIG_ENABLE_CONNTRACK;
    __u32 *enabled = bpf_map_lookup_elem(&global_config, &key);
    if (!enabled || *enabled != 1) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0;
    __u8 protocol = 0;

    // Handle IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return TC_ACT_OK;

        protocol = ip->protocol;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                // Extract flags for fine-grained tracking
                if (tcp->syn) tcp_flags |= 1;
                if (tcp->fin) tcp_flags |= 2;
                if (tcp->rst) tcp_flags |= 4;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + sizeof(*ip);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }

        if (src_port == 0 || dst_port == 0)
            return TC_ACT_OK;

        // Fine-grained TCP state tracking:
        // Only create new entries for SYN packets to prevent scanning from filling CT table.
        // For UDP, we always create/update.
        if (protocol == IPPROTO_TCP) {
            struct ct_key ct_key = {
                .src_ip = ip->saddr,
                .dst_ip = ip->daddr,
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = protocol,
            };

            // If it's a SYN, create or refresh.
            // If it's FIN/RST, we could shorten the timeout, but for now just update last_seen.
            // A more advanced version would use a different timeout for FIN_WAIT.
            if (tcp_flags & 1) { // SYN
                struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
                bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
            } else {
                // For non-SYN TCP, only update if entry already exists.
                struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map, &ct_key);
                if (exists) {
                    exists->last_seen = bpf_ktime_get_ns();
                }
            }
        } else {
            // UDP/other: always update
            struct ct_key ct_key = {
                .src_ip = ip->saddr,
                .dst_ip = ip->daddr,
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = protocol,
            };
            struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
            bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
        }
    }
    // Handle IPv6
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
            return TC_ACT_OK;

        protocol = ip6->nexthdr;
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
                if (tcp->fin) tcp_flags |= 2;
                if (tcp->rst) tcp_flags |= 4;
            }
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip6 + sizeof(*ip6);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }

        if (src_port == 0 || dst_port == 0)
            return TC_ACT_OK;

        if (protocol == IPPROTO_TCP) {
            struct ct_key6 ct_key = {
                .src_ip = ip6->saddr,
                .dst_ip = ip6->daddr,
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = protocol,
            };

            if (tcp_flags & 1) { // SYN
                struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
                bpf_map_update_elem(&conntrack_map6, &ct_key, &ct_val, BPF_ANY);
            } else {
                struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map6, &ct_key);
                if (exists) {
                    exists->last_seen = bpf_ktime_get_ns();
                }
            }
        } else {
            struct ct_key6 ct_key = {
                .src_ip = ip6->saddr,
                .dst_ip = ip6->daddr,
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = protocol,
            };
            struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
            bpf_map_update_elem(&conntrack_map6, &ct_key, &ct_val, BPF_ANY);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
