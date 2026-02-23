// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
#ifndef __NETXFW_RATELIMIT_BPF_C
#define __NETXFW_RATELIMIT_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"

/**
 * Helper to check general rate limit for an IP address (IPv4-mapped or IPv6)
 * Uses the unified ratelimit_map (config + state combined)
 * 检查 IP 地址（IPv4 映射或 IPv6）的通用速率限制的辅助函数
 * 使用统一的 ratelimit_map（配置 + 状态合并）
 */
static __always_inline int check_ratelimit(struct in6_addr *ip) {
    struct ratelimit_value *val = bpf_map_lookup_elem(&ratelimit_map, ip);
    
    // 1. If we have an entry, check rate limit
    // 1. 如果有条目，检查速率限制
    if (likely(val)) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - val->last_time;
        
        // Fast path: < 1ms, skip math
        // 快速路径：< 1ms，跳过数学运算
        if (likely(elapsed < 1000000ULL)) {
            if (likely(val->tokens >= 1)) {
                val->tokens -= 1;
                return 1;
            }
            // Rate limit exceeded: Auto-block if enabled
            // 超出速率限制：如果启用，则自动阻止
            add_to_blacklist(ip);
            return 0;
        }

        // Calculate new tokens based on elapsed time
        // Using pre-scaled rate to avoid division: (elapsed * rate_scaled) >> 32
        // 根据经过的时间计算新令牌
        // 使用预缩放速率避免除法：(elapsed * rate_scaled) >> 32
        __u64 tokens_to_add = (elapsed * val->rate_scaled) >> 32;
        __u64 new_tokens = val->tokens + tokens_to_add;
        if (new_tokens > val->burst) new_tokens = val->burst;

        if (likely(new_tokens >= 1)) {
            val->tokens = new_tokens - 1;
            val->last_time = now;
            return 1;
        }

        // Rate limit exceeded: Auto-block if enabled
        // 超出速率限制：如果启用，则自动阻止
        add_to_blacklist(ip);
        return 0;
    }

    // 2. No entry found: allow by default (no rate limit configured for this IP)
    // 2. 未找到条目：默认允许（此 IP 未配置速率限制）
    return 1;
}

/**
 * Initialize rate limit for an IP (called from userspace via map update)
 * 为 IP 初始化速率限制（通过 Map 更新从用户空间调用）
 * The userspace should set:
 * 用户空间应设置：
 * - rate: packets per second / 每秒数据包数
 * - burst: max tokens / 最大令牌数
 * - config_version: for hot reload tracking / 用于热加载跟踪
 * - last_time: current time / 当前时间
 * - tokens: initial tokens (usually = burst) / 初始令牌（通常 = burst）
 */

#endif // __NETXFW_RATELIMIT_BPF_C
