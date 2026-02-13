// SPDX-License-Identifier: MIT
#ifndef __NETXFW_STATS_BPF_C
#define __NETXFW_STATS_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"

static __always_inline void update_pass_stats() {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pass_stats, &key);
    if (count) *count += 1;
}

static __always_inline void update_pass_stats_with_reason(__u32 reason, __u32 protocol, struct in6_addr *src_ip, __u16 dst_port) {
    // Update global pass counter
    update_pass_stats();

    // Update detailed pass stats
    struct drop_detail_key dkey = {};
    dkey.reason = reason;
    dkey.protocol = protocol;
    if (src_ip) {
        __builtin_memcpy(&dkey.src_ip, src_ip, sizeof(struct in6_addr));
    }
    dkey.dst_port = dst_port;

    __u64 *count = bpf_map_lookup_elem(&pass_reason_stats, &dkey);
    if (count) {
        *count += 1;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&pass_reason_stats, &dkey, &init_val, BPF_ANY);
    }
}

static __always_inline void update_drop_stats_with_reason(__u32 reason, __u32 protocol, struct in6_addr *src_ip, __u16 dst_port) {
    // Update global drop counter
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
    if (count) {
        *count += 1;
    }

    // Update detailed drop stats
    struct drop_detail_key dkey = {};
    dkey.reason = reason;
    dkey.protocol = protocol;
    if (src_ip) {
        __builtin_memcpy(&dkey.src_ip, src_ip, sizeof(struct in6_addr));
    }
    dkey.dst_port = dst_port;

    count = bpf_map_lookup_elem(&drop_reason_stats, &dkey);
    if (count) {
        *count += 1;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&drop_reason_stats, &dkey, &init_val, BPF_ANY);
    }
}

static __always_inline void update_drop_stats() {
    // For unknown drop, we use zero address
    struct in6_addr zero_ip = {};
    update_drop_stats_with_reason(DROP_REASON_UNKNOWN, 0, &zero_ip, 0);
}

#endif // __NETXFW_STATS_BPF_C
