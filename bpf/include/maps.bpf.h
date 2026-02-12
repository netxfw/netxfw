// SPDX-License-Identifier: MIT
#ifndef __NETXFW_MAPS_H
#define __NETXFW_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in6.h>
#include "bpf_features.h"

/**
 * Common structures
 */
struct ct_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
} __attribute__((packed));

struct ct_key6 {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
} __attribute__((packed));

struct ct_value {
    __u64 last_seen;
};

struct lpm_key4 {
    __u32 prefixlen;
    __u32 data;
};

struct lpm_key6 {
    __u32 prefixlen;
    struct in6_addr data;
};

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

struct rule_value {
    __u64 counter;
    __u64 expires_at;
};

struct ratelimit_stats {
    __u64 last_time;
    __u64 tokens;
    __u64 rate;
    __u64 burst;
    __u64 config_version;
};

struct ratelimit_conf {
    __u64 rate;  // packets per second
    __u64 burst; // max tokens
};

struct icmp_stats {
    __u64 last_time;
    __u64 tokens;
};

/**
 * Map Definitions
 */

#ifdef ENABLE_IPV6
#define CT_MAP_SIZE 100000
#define LPM_MAP_SIZE 65536
#define LOCK_LIST_SIZE 1000000
#else
#define CT_MAP_SIZE 1
#define LPM_MAP_SIZE 1
#define LOCK_LIST_SIZE 1
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct ct_key);
    __type(value, struct ct_value);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_SIZE);
    __type(key, struct ct_key6);
    __type(value, struct ct_value);
} conntrack_map6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key4);
    __type(value, struct ratelimit_conf);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ratelimit_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAP_SIZE);
    __type(key, struct lpm_key6);
    __type(value, struct ratelimit_conf);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ratelimit_config6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct ratelimit_stats);
} ratelimit_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_SIZE);
    __type(key, struct in6_addr);
    __type(value, struct ratelimit_stats);
} ratelimit_state6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 2000000);
    __type(key, struct lpm_key4);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, struct rule_value);
} dyn_lock_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LOCK_LIST_SIZE);
    __type(key, struct lpm_key6);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct in6_addr);
    __type(value, struct rule_value);
} dyn_lock_list6 SEC(".maps");

struct drop_detail_key {
    __u32 reason;
    __u32 protocol;
    __u32 src_ip;
    __u16 dst_port;
    __u16 pad;
} __attribute__((packed));

struct drop_detail_key6 {
    __u32 reason;
    __u32 protocol;
    struct in6_addr src_ip;
    __u16 dst_port;
    __u16 pad;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct drop_detail_key);
    __type(value, __u64);
} drop_reason_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct drop_detail_key6);
    __type(value, __u64);
} drop_reason_stats6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pass_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct drop_detail_key);
    __type(value, __u64);
} pass_reason_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct drop_detail_key6);
    __type(value, __u64);
} pass_reason_stats6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_stats);
} icmp_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key4);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAP_SIZE);
    __type(key, struct lpm_key6);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct rule_value);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_ip4_port_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_port_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAP_SIZE);
    __type(key, struct lpm_ip6_port_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_port_rules6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsk_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} global_config SEC(".maps");

// Optimization: Packet counter for config refresh sampling (Per-CPU to avoid contention)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_counter SEC(".maps");

#endif // __NETXFW_MAPS_H
