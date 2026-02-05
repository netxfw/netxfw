// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#include "include/protocol.h"
#include "include/maps.bpf.h"
#include "include/helpers.bpf.h"
#include "include/config.bpf.h"
#include "include/bpf_features.h"

// Global cached config variables (referenced by extern in helpers.bpf.h)
__u64 cached_version = 0;
__u32 cached_default_deny = 0;
__u32 cached_allow_return = 0;
__u32 cached_allow_icmp = 0;
__u32 cached_ct_enabled = 0;
__u64 cached_ct_timeout = 0;
__u32 cached_icmp_rate = 0;
__u32 cached_icmp_burst = 0;
__u32 cached_af_xdp_enabled = 0;
__u32 cached_strict_proto = 0;
__u32 cached_ratelimit_enabled = 0;
__u32 cached_drop_frags = 0;
__u32 cached_strict_tcp = 0;
__u32 cached_syn_limit = 0;
__u32 cached_bogon_filter = 0;
__u32 cached_auto_block = 0;
__u64 cached_auto_block_expiry = 0;

// Include functional modules
#include "modules/stats.bpf.c"
#include "modules/conntrack.bpf.c"

// Include protocol handlers
#include "protocols/ipv4.bpf.c"
#ifdef ENABLE_IPV6
#include "protocols/ipv6.bpf.c"
#endif

SEC("xdp/ipv4")
int xdp_ipv4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;

    int action = handle_ipv4(ctx, data, data_end, eth);
    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        update_pass_stats();
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        update_drop_stats();
        return XDP_DROP;
    }
    return action;
}

SEC("xdp/ipv6")
int xdp_ipv6(struct xdp_md *ctx) {
#ifdef ENABLE_IPV6
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;

    int action = handle_ipv6(ctx, data, data_end, eth);
    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        update_pass_stats();
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        update_drop_stats();
        return XDP_DROP;
    }
    return action;
#else
    return XDP_PASS;
#endif
}

/**
 * Main XDP firewall program
 * XDP 防火墙主程序
 */
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    refresh_config();

    // Try to call the first plugin slot / 尝试调用第一个插件槽位
    // If a plugin is loaded, it's responsible for tail-calling the next plugin or the core logic
    // 如果加载了插件，它负责尾调用下一个插件或核心逻辑
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_PLUGIN_START);

    if (h_proto == bpf_htons(ETH_P_IP)) {
        bpf_tail_call(ctx, &jmp_table, PROG_IDX_IPV4);
        // Fallback if tail call fails
        return handle_ipv4(ctx, data, data_end, eth);
    } 
#ifdef ENABLE_IPV6
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_tail_call(ctx, &jmp_table, PROG_IDX_IPV6);
        // Fallback if tail call fails
        return handle_ipv6(ctx, data, data_end, eth);
    } 
#endif
    else if (h_proto == bpf_htons(ETH_P_ARP)) {
        return XDP_PASS;
    } else {
        if (cached_strict_proto == 1) {
            update_drop_stats();
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
