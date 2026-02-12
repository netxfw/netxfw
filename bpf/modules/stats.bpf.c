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

static __always_inline void update_drop_stats_with_reason(__u32 reason, __u32 protocol, __u32 src_ip, __u16 dst_port) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
    if (count) *count += 1;

    struct drop_detail_key dkey = {};
    dkey.reason = reason;
    dkey.protocol = protocol;
    dkey.src_ip = src_ip;
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
    update_drop_stats_with_reason(DROP_REASON_UNKNOWN, 0, 0, 0);
}

#endif // __NETXFW_STATS_BPF_C
