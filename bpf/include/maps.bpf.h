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

// Conntrack value
// 连接跟踪值
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

// Unified LPM IP+Port Key (for rule_map)
// 统一的 LPM IP+端口键（用于 rule_map）
struct lpm_ip_port_key {
    __u32 prefixlen;
    __u16 port;
    __u16 pad;
    struct in6_addr ip;
};

// Rule value (for blacklist, whitelist, rule_map)
// 规则值（用于黑名单、白名单、规则 Map）
struct rule_value {
    __u64 counter;     // Packet counter / 数据包计数器
    __u64 expires_at;  // Expiry timestamp (0 = never) / 过期时间戳（0 = 永不过期）
    __u8  action;      // Action: 1=allow, 2=deny / 动作：1=允许，2=拒绝
    __u8  priority;    // Priority for rule ordering / 规则优先级
    __u8  _pad[6];
};

// Rate limit combined value (config + state)
// 速率限制合并值（配置 + 状态）
struct ratelimit_value {
    // Config part / 配置部分
    __u64 rate;            // Packets per second / 每秒数据包数
    __u64 burst;           // Max tokens / 最大令牌数
    __u64 config_version;  // Config version for hot reload / 配置版本用于热加载
    // State part / 状态部分
    __u64 last_time;       // Last update time / 上次更新时间
    __u64 tokens;          // Current tokens / 当前令牌数
};

// Global statistics structure
// 全局统计结构
struct stats_global {
    // Packet counters / 数据包计数器
    __u64 total_packets;    // Total packets processed / 处理的总数据包
    __u64 total_pass;       // Total passed packets / 通过的总数据包
    __u64 total_drop;       // Total dropped packets / 丢弃的总数据包
    
    // Drop reason counters / 丢弃原因计数器
    __u64 drop_blacklist;      // Dropped by blacklist / 被黑名单丢弃
    __u64 drop_no_rule;        // Dropped: no matching rule / 丢弃：无匹配规则
    __u64 drop_invalid;        // Dropped: invalid packet / 丢弃：无效数据包
    __u64 drop_rate_limit;     // Dropped: rate limit / 丢弃：速率限制
    __u64 drop_syn_flood;      // Dropped: SYN flood / 丢弃：SYN 洪水
    __u64 drop_icmp_limit;     // Dropped: ICMP limit / 丢弃：ICMP 限制
    __u64 drop_port_blocked;   // Dropped: port blocked / 丢弃：端口被阻止
    
    // Pass reason counters / 通过原因计数器
    __u64 pass_whitelist;      // Passed by whitelist / 被白名单通过
    __u64 pass_rule;           // Passed by rule / 被规则通过
    __u64 pass_return;         // Passed: return traffic / 通过：回程流量
    __u64 pass_established;    // Passed: established connection / 通过：已建立连接
    
    // ICMP rate limit state / ICMP 速率限制状态
    __u64 icmp_last_time;      // Last ICMP packet time / 上次 ICMP 数据包时间
    __u64 icmp_tokens;         // ICMP tokens / ICMP 令牌
    
    // Config version / 配置版本
    __u64 config_version;      // Current config version / 当前配置版本
    __u64 _reserved[8];        // Reserved for future use / 保留供将来使用
};

// Top stats key (for top_drop_map, top_pass_map)
// Top 统计键（用于 top_drop_map, top_pass_map）
struct top_stats_key {
    __u32 reason;           // Reason code / 原因代码
    __u32 protocol;         // Protocol (TCP/UDP/ICMP) / 协议
    struct in6_addr src_ip; // Source IP / 源 IP
    __u16 dst_port;         // Destination port / 目标端口
    __u16 pad;
};

/**
 * Map Definitions
 * Map 定义
 */

// Map size constants
// Map 大小常量
#define CT_MAP_SIZE            100000    // Conntrack entries / 连接跟踪条目
#define RATELIMIT_MAP_SIZE     100000    // Rate limit entries / 速率限制条目
#define STATIC_BLACKLIST_SIZE  2000000   // Static blacklist entries / 静态黑名单条目
#define DYNAMIC_BLACKLIST_SIZE 1000000   // Dynamic blacklist entries / 动态黑名单条目
#define CRITICAL_BLACKLIST_SIZE 10000    // Critical blacklist entries / 危机封锁条目
#define WHITELIST_SIZE         100000    // Whitelist entries / 白名单条目
#define RULE_MAP_SIZE          100000    // IP+Port rule entries / IP+端口规则条目
#define STATS_GLOBAL_SIZE      64        // Global stats slots / 全局统计槽位
#define TOP_STATS_SIZE         1024      // Top stats entries / Top 统计条目
#define GLOBAL_CONFIG_SIZE     32        // Global config slots / 全局配置槽位

/**
 * 1. conntrack_map - Connection tracking
 * 1. conntrack_map - 连接跟踪
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_SIZE);
    __type(key, struct ct_key);
    __type(value, struct ct_value);
} conntrack_map SEC(".maps");

/**
 * 2. ratelimit_map - Rate limit (config + state combined)
 * 2. ratelimit_map - 速率限制（配置 + 状态合并）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATELIMIT_MAP_SIZE);
    __type(key, struct in6_addr);  // Key is IP / 键为 IP
    __type(value, struct ratelimit_value);
} ratelimit_map SEC(".maps");

/**
 * 3. static_blacklist - Static blacklist (persistent rules)
 * 3. static_blacklist - 静态黑名单（持久化规则）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, STATIC_BLACKLIST_SIZE);
    __type(key, struct lpm_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} static_blacklist SEC(".maps");

/**
 * 4. dynamic_blacklist - Dynamic blacklist (auto-blocking, auto-expiry)
 * 4. dynamic_blacklist - 动态黑名单（自动阻止，自动过期）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DYNAMIC_BLACKLIST_SIZE);
    __type(key, struct in6_addr);  // Key is IP / 键为 IP
    __type(value, struct rule_value);
} dynamic_blacklist SEC(".maps");

/**
 * 5. critical_blacklist - Critical blacklist (highest priority, never auto-evict)
 * 5. critical_blacklist - 危机封锁（最高优先级，永不自动淘汰）
 * Used for emergency blocking of attack sources
 * 用于紧急封锁攻击源
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CRITICAL_BLACKLIST_SIZE);
    __type(key, struct in6_addr);  // Key is IP / 键为 IP
    __type(value, struct rule_value);
} critical_blacklist SEC(".maps");

/**
 * 6. whitelist - Whitelist (allowed IPs/CIDRs)
 * 6. whitelist - 白名单（允许的 IP/CIDR）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, WHITELIST_SIZE);
    __type(key, struct lpm_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

/**
 * 7. rule_map - IP+Port rules (combined allowed_ports + ip_port_rules)
 * 7. rule_map - IP+端口规则（合并 allowed_ports + ip_port_rules）
 * Port 0 means "all ports" for IP-level rules
 * 端口 0 表示 IP 级别规则（所有端口）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, RULE_MAP_SIZE);
    __type(key, struct lpm_ip_port_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_map SEC(".maps");

/**
 * 8. stats_global_map - Global statistics (all counters combined)
 * 8. stats_global_map - 全局统计（所有计数器合并）
 * Index 0: main stats structure / 索引 0：主统计结构
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_GLOBAL_SIZE);
    __type(key, __u32);
    __type(value, struct stats_global);
} stats_global_map SEC(".maps");

/**
 * 9. top_drop_map - Top drop statistics (top N dropped IPs/ports)
 * 9. top_drop_map - Top 丢弃统计（Top N 被丢弃的 IP/端口）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TOP_STATS_SIZE);
    __type(key, struct top_stats_key);
    __type(value, __u64);
} top_drop_map SEC(".maps");

/**
 * 10. top_pass_map - Top pass statistics (top N passed IPs/ports)
 * 10. top_pass_map - Top 通过统计（Top N 被通过的 IP/端口）
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TOP_STATS_SIZE);
    __type(key, struct top_stats_key);
    __type(value, __u64);
} top_pass_map SEC(".maps");

/**
 * 11. xsk_map - AF_XDP socket map
 * 11. xsk_map - AF_XDP socket 映射
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsk_map SEC(".maps");

/**
 * 12. jmp_table - Program tail call table
 * 12. jmp_table - 程序尾调用表
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

/**
 * 13. global_config - Global configuration
 * 13. global_config - 全局配置
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, GLOBAL_CONFIG_SIZE);
    __type(key, __u32);
    __type(value, __u64);
} global_config SEC(".maps");

/**
 * Backward compatibility aliases (deprecated, will be removed)
 * 向后兼容别名（已弃用，将被移除）
 */
#define lock_list        static_blacklist
#define dyn_lock_list    dynamic_blacklist
#define drop_reason_stats top_drop_map
#define pass_reason_stats top_pass_map

#endif // __NETXFW_MAPS_H
