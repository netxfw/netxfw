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

static __always_inline void update_drop_stats() {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
    if (count) *count += 1;
}

#endif // __NETXFW_STATS_BPF_C
