// SPDX-License-Identifier: MIT
#ifndef __NETXFW_HELPERS_H
#define __NETXFW_HELPERS_H

#include "maps.bpf.h"

#define CONFIG_DEFAULT_DENY 0
#define CONFIG_ALLOW_RETURN_TRAFFIC 1
#define CONFIG_ALLOW_ICMP 2
#define CONFIG_ENABLE_CONNTRACK 3
#define CONFIG_CONNTRACK_TIMEOUT 4
#define CONFIG_ICMP_RATE 5
#define CONFIG_ICMP_BURST 6
#define CONFIG_ENABLE_AF_XDP 7
#define CONFIG_CONFIG_VERSION 8
#define CONFIG_STRICT_PROTO 9
#define CONFIG_ENABLE_RATELIMIT 10
#define CONFIG_DROP_FRAGMENTS 11
#define CONFIG_STRICT_TCP 12
#define CONFIG_SYN_LIMIT 13
#define CONFIG_BOGON_FILTER 14

// Global cached config (static inlines can access these if defined in the main file or here)
// For simplicity and correctness in BPF, we'll keep the cache variables in the main file 
// but define the logic here as macros or always_inline functions that take parameters.

// Global cached config version (defined in config.bpf.h)
extern __u64 cached_version;

/**
 * Check if an IPv4 address is a Bogon (reserved/private)
 */
static __always_inline int is_bogon_ipv4(__u32 ip) {
    __u32 host_ip = bpf_ntohl(ip);
    
    // 0.0.0.0/8
    if ((host_ip & 0xFF000000) == 0x00000000) return 1;
    // 127.0.0.0/8 (Loopback)
    if ((host_ip & 0xFF000000) == 0x7F000000) return 1;
    // 169.254.0.0/16 (Link Local)
    if ((host_ip & 0xFFFF0000) == 0xA9FE0000) return 1;
    // 224.0.0.0/4 (Multicast/Reserved)
    if ((host_ip & 0xF0000000) == 0xE0000000) return 1;
    // 240.0.0.0/4 (Reserved)
    if ((host_ip & 0xF0000000) == 0xF0000000) return 1;
    
    return 0;
}

/**
 * Check if an IPv6 address is a Bogon (reserved/private)
 */
static __always_inline int is_bogon_ipv6(struct in6_addr *ip) {
    // ::/128 (Unspecified)
    if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 &&
        ip->s6_addr32[2] == 0 && ip->s6_addr32[3] == 0) return 1;
    
    // ::1/128 (Loopback)
    if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 &&
        ip->s6_addr32[2] == 0 && ip->s6_addr32[3] == bpf_htonl(1)) return 1;

    // ff00::/8 (Multicast)
    if (ip->s6_addr[0] == 0xff) return 1;

    // fe80::/10 (Link-Local)
    if (ip->s6_addr[0] == 0xfe && (ip->s6_addr[1] & 0xc0) == 0x80) return 1;

    return 0;
}

/**
 * Validate TCP Flags (detect Null, Xmas, etc.)
 */
static __always_inline int is_invalid_tcp_flags(__u8 flags) {
    // 1. Null scan (no flags set)
    if (flags == 0) return 1;
    // 2. Xmas scan (FIN, PSH, URG set)
    if (flags == 0x29) return 1;
    // 3. SYN and FIN set
    if ((flags & 0x01) && (flags & 0x02)) return 1;
    // 4. FIN without ACK (rare but usually malicious)
    if ((flags & 0x01) && !(flags & 0x10)) return 1;
    
    return 0;
}

/**
 * Helper to check general rate limit for an IPv4 address
 */
static __always_inline int check_ratelimit(__u32 ip) {
    struct ratelimit_stats *stats = bpf_map_lookup_elem(&ratelimit_state, &ip);
    
    // 1. If we have a cached state, check if the config version is still valid
    if (stats && stats->config_version == cached_version) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - stats->last_time;
        
        // Fast path: < 1ms, skip math
        if (elapsed < 1000000ULL) {
            if (stats->tokens >= 1) {
                stats->tokens -= 1;
                return 1;
            }
            return 0;
        }

        __u64 tokens_to_add = (elapsed * stats->rate) / 1000000000ULL;
        __u64 new_tokens = stats->tokens + tokens_to_add;
        if (new_tokens > stats->burst) new_tokens = stats->burst;

        if (new_tokens >= 1) {
            stats->tokens = new_tokens - 1;
            stats->last_time = now;
            return 1;
        }
        return 0;
    }

    // 2. No state or stale config: lookup CIDR configuration (LPM)
    struct lpm_key4 key = { .prefixlen = 32, .data = ip };
    struct ratelimit_conf *conf = bpf_map_lookup_elem(&ratelimit_config, &key);
    if (!conf) return 1;

    // 3. Update or create state with new config
    if (stats) {
        stats->rate = conf->rate;
        stats->burst = conf->burst;
        stats->config_version = cached_version;
        // Keep current tokens/last_time or reset? Resetting is safer for config changes.
        stats->tokens = conf->burst;
        stats->last_time = bpf_ktime_get_ns();
    } else {
        struct ratelimit_stats new_stats = {
            .last_time = bpf_ktime_get_ns(),
            .tokens = conf->burst,
            .rate = conf->rate,
            .burst = conf->burst,
            .config_version = cached_version,
        };
        bpf_map_update_elem(&ratelimit_state, &ip, &new_stats, BPF_ANY);
    }
    return 1;
}

/**
 * Helper to check general rate limit for an IPv6 address
 */
static __always_inline int check_ratelimit6(struct in6_addr *ip) {
    struct ratelimit_stats *stats = bpf_map_lookup_elem(&ratelimit_state6, ip);

    if (stats && stats->config_version == cached_version) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - stats->last_time;

        if (elapsed < 1000000ULL) {
            if (stats->tokens >= 1) {
                stats->tokens -= 1;
                return 1;
            }
            return 0;
        }

        __u64 tokens_to_add = (elapsed * stats->rate) / 1000000000ULL;
        __u64 new_tokens = stats->tokens + tokens_to_add;
        if (new_tokens > stats->burst) new_tokens = stats->burst;

        if (new_tokens >= 1) {
            stats->tokens = new_tokens - 1;
            stats->last_time = now;
            return 1;
        }
        return 0;
    }

    struct lpm_key6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));

    struct ratelimit_conf *conf = bpf_map_lookup_elem(&ratelimit_config6, &key);
    if (!conf) return 1;

    if (stats) {
        stats->rate = conf->rate;
        stats->burst = conf->burst;
        stats->config_version = cached_version;
        stats->tokens = conf->burst;
        stats->last_time = bpf_ktime_get_ns();
    } else {
        struct ratelimit_stats new_stats = {
            .last_time = bpf_ktime_get_ns(),
            .tokens = conf->burst,
            .rate = conf->rate,
            .burst = conf->burst,
            .config_version = cached_version,
        };
        bpf_map_update_elem(&ratelimit_state6, ip, &new_stats, BPF_ANY);
    }
    return 1;
}

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

static __always_inline int is_whitelisted6(struct in6_addr *ip, __u16 port) {
    struct lpm_key6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    struct rule_value *val = bpf_map_lookup_elem(&whitelist6, &key);
    if (!val) return 0;
    if (val->counter > 1 && val->counter != port) return 0;
    return 1;
}

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

static __always_inline struct rule_value *get_lock_stats(__u32 ip) {
    struct lpm_key4 key = { .prefixlen = 32, .data = ip };
    return bpf_map_lookup_elem(&lock_list, &key);
}

static __always_inline struct rule_value *get_lock_stats6(struct in6_addr *ip) {
    struct lpm_key6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));
    return bpf_map_lookup_elem(&lock_list6, &key);
}

static __always_inline int check_icmp_limit(__u64 rate, __u64 burst) {
    __u32 key = 0;
    struct icmp_stats *stats = bpf_map_lookup_elem(&icmp_limit_map, &key);
    if (!stats) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - stats->last_time;
    __u64 tokens_to_add = (elapsed * rate) / 1000000000ULL;

    __u64 new_tokens = stats->tokens + tokens_to_add;
    if (new_tokens > burst) new_tokens = burst;

    if (new_tokens >= 1) {
        stats->tokens = new_tokens - 1;
        stats->last_time = now;
        return 1;
    }
    return 0;
}

#endif // __NETXFW_HELPERS_H
