// SPDX-License-Identifier: MIT
#ifndef __NETXFW_MAPS_H
#define __NETXFW_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in6.h>
#include "bpf_features.h"

/**
 * Common structures
 * 通用结构体
 */

// Unified Conntrack Key (IPv6 size for all)
// 统一连接跟踪键（所有协议使用 IPv6 大小）
struct ct_key {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
};

struct ct_value {
    __u64 last_seen;
};

// Unified LPM Key for IPv4/IPv6
// IPv4 addresses are stored as IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
// 统一的 IPv4/IPv6 LPM 键
// IPv4 地址存储为 IPv4 映射的 IPv6 地址 (::ffff:a.b.c.d)
struct lpm_key {
    __u32 prefixlen;
    struct in6_addr data;
};

// Unified LPM IP+Port Key
// 统一的 LPM IP+端口键
struct lpm_ip_port_key {
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
    __u64 rate;  // packets per second / 每秒数据包数
    __u64 burst; // max tokens / 最大令牌数
};

struct icmp_stats {
    __u64 last_time;
    __u64 tokens;
};

// Unified Drop/Pass Detail Key
// 统一丢弃/通过详细信息键
struct drop_detail_key {
    __u32 reason;
    __u32 protocol;
    struct in6_addr src_ip;
    __u16 dst_port;
    __u16 pad;
};

/**
 * Map Definitions
 * Map 定义
 */

#define CT_MAP_SIZE 100000
#define LPM_MAP_SIZE 100000
#define LOCK_LIST_SIZE 2000000

// Stats Map Sizes (per minute capacity)
// 统计 Map 大小（每分钟容量）
// Default: 1 million entries per minute for high-traffic scenarios
// 默认：每分钟 100 万条目，适用于高流量场景
#define DROP_STATS_SIZE 1000000
#define PASS_STATS_SIZE 1000000

// Unified Conntrack Map
// 统一连接跟踪 Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_SIZE);
    __type(key, struct ct_key);
    __type(value, struct ct_value);
} conntrack_map SEC(".maps");

// Unified Rate Limit Config (LPM TRIE)
// 统一速率限制配置 (LPM TRIE)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAP_SIZE);
    __type(key, struct lpm_key);
    __type(value, struct ratelimit_conf);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ratelimit_config SEC(".maps");

// Unified Rate Limit State (LRU HASH)
// 统一速率限制状态 (LRU HASH)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct in6_addr); // Key is just IP / 键仅为 IP
    __type(value, struct ratelimit_stats);
} ratelimit_state SEC(".maps");

// Unified Lock List (LPM TRIE) - Static rules
// 统一锁定列表 (LPM TRIE) - 静态规则
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LOCK_LIST_SIZE);
    __type(key, struct lpm_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lock_list SEC(".maps");

// Unified Dynamic Lock List (LRU HASH) - Auto blocking
// 统一动态锁定列表 (LRU HASH) - 自动阻止
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct in6_addr); // Key is just IP / 键仅为 IP
    __type(value, struct rule_value);
} dyn_lock_list SEC(".maps");

// Unified Drop Stats (Per-CPU Array) - Global counters
// 统一丢弃统计 (Per-CPU Array) - 全局计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

// Unified Drop Reason Stats (LRU HASH) - Detailed stats with auto-eviction
// 统一丢弃原因统计 (LRU HASH) - 详细统计，自动淘汰旧条目
// Supports top IP / top port analysis with bounded memory
// 支持带内存限制的 top IP / top port 分析
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DROP_STATS_SIZE);
    __type(key, struct drop_detail_key);
    __type(value, __u64);
} drop_reason_stats SEC(".maps");

// Unified Pass Stats (Per-CPU Array) - Global counters
// 统一通过统计 (Per-CPU Array) - 全局计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pass_stats SEC(".maps");

// Unified Pass Reason Stats (LRU HASH) - Detailed stats with auto-eviction
// 统一通过原因统计 (LRU HASH) - 详细统计，自动淘汰旧条目
// Supports top IP / top port analysis with bounded memory
// 支持带内存限制的 top IP / top port 分析
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PASS_STATS_SIZE);
    __type(key, struct drop_detail_key);
    __type(value, __u64);
} pass_reason_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_stats);
} icmp_limit_map SEC(".maps");

// Unified Whitelist (LPM TRIE)
// 统一白名单 (LPM TRIE)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAP_SIZE);
    __type(key, struct lpm_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct rule_value);
} allowed_ports SEC(".maps");

// Unified IP+Port Rules (LPM TRIE)
// 统一 IP+端口规则 (LPM TRIE)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAP_SIZE);
    __type(key, struct lpm_ip_port_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_port_rules SEC(".maps");

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
    __uint(max_entries, 1024);
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
