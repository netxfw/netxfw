// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
#ifndef __NETXFW_ICMP_BPF_C
#define __NETXFW_ICMP_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"

/**
 * Check ICMP rate limit using stats_global_map
 * 使用 stats_global_map 检查 ICMP 速率限制
 */
static __always_inline int check_icmp_limit(__u64 rate, __u64 burst) {
    __u32 key = 0;
    struct stats_global *stats = bpf_map_lookup_elem(&stats_global_map, &key);
    if (!stats) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - stats->icmp_last_time;
    
    // Fast path: < 1ms, skip math
    // 快速路径：< 1ms，跳过数学运算
    if (elapsed < 1000000ULL) {
        if (stats->icmp_tokens >= 1) {
            stats->icmp_tokens -= 1;
            return 1;
        }
        return 0;
    }

    __u64 tokens_to_add = (elapsed * rate) / 1000000000ULL;
    __u64 new_tokens = stats->icmp_tokens + tokens_to_add;
    if (new_tokens > burst) new_tokens = burst;

    if (new_tokens >= 1) {
        stats->icmp_tokens = new_tokens - 1;
        stats->icmp_last_time = now;
        return 1;
    }
    return 0;
}

#endif // __NETXFW_ICMP_BPF_C
