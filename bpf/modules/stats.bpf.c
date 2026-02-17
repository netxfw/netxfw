// SPDX-License-Identifier: MIT
#ifndef __NETXFW_STATS_BPF_C
#define __NETXFW_STATS_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"

static __always_inline void update_pass_stats() {
    __u32 key = 0;
    struct stats_global *stats = bpf_map_lookup_elem(&stats_global_map, &key);
    if (stats) {
        stats->total_pass += 1;
        stats->total_packets += 1;
    }
}

static __always_inline void update_pass_stats_with_reason(__u32 reason, __u32 protocol, struct in6_addr *src_ip, __u16 dst_port) {
    // Update global pass counter
    // 更新全局通过计数器
    update_pass_stats();

    // Update detailed pass stats using top_pass_map
    // 使用 top_pass_map 更新详细通过统计信息
    struct top_stats_key dkey = {};
    dkey.reason = reason;
    dkey.protocol = protocol;
    if (src_ip) {
        __builtin_memcpy(&dkey.src_ip, src_ip, sizeof(struct in6_addr));
    }
    dkey.dst_port = dst_port;

    __u64 *count = bpf_map_lookup_elem(&top_pass_map, &dkey);
    if (count) {
        *count += 1;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&top_pass_map, &dkey, &init_val, BPF_ANY);
    }
}

static __always_inline void update_drop_stats_with_reason(__u32 reason, __u32 protocol, struct in6_addr *src_ip, __u16 dst_port) {
    // Update global drop counter
    // 更新全局丢弃计数器
    __u32 key = 0;
    struct stats_global *stats = bpf_map_lookup_elem(&stats_global_map, &key);
    if (stats) {
        stats->total_drop += 1;
        stats->total_packets += 1;
    }

    // Update detailed drop stats using top_drop_map
    // 使用 top_drop_map 更新详细丢弃统计信息
    struct top_stats_key dkey = {};
    dkey.reason = reason;
    dkey.protocol = protocol;
    if (src_ip) {
        __builtin_memcpy(&dkey.src_ip, src_ip, sizeof(struct in6_addr));
    }
    dkey.dst_port = dst_port;

    __u64 *count = bpf_map_lookup_elem(&top_drop_map, &dkey);
    if (count) {
        *count += 1;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&top_drop_map, &dkey, &init_val, BPF_ANY);
    }
}

static __always_inline void update_drop_stats() {
    // For unknown drop, we use zero address
    // 对于未知丢弃，我们使用零地址
    struct in6_addr zero_ip = {};
    update_drop_stats_with_reason(DROP_REASON_UNKNOWN, 0, &zero_ip, 0);
}

#endif // __NETXFW_STATS_BPF_C
