// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NetXfw BPF Program - Kernel Space XDP Firewall
 * 
 * This BPF program uses GPL-only kernel helper functions and must be
 * licensed under GPL-2.0-or-later for kernel compatibility.
 * 
 * For commercial licensing options, please contact the copyright holder.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#include "include/protocol.h"
#include "include/maps.bpf.h"
#include "include/helpers.bpf.h"
#include "include/config.bpf.h"
#include "include/bpf_features.h"

// Global cached config variables (referenced by extern in helpers.bpf.h)
// 全局缓存的配置变量（在 helpers.bpf.h 中通过 extern 引用）
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
// 包含功能模块
#include "modules/stats.bpf.c"
#include "modules/conntrack.bpf.c"

// Include protocol handlers
// 包含协议处理器
#include "protocols/ipv4.bpf.c"
#ifdef ENABLE_IPV6
#include "protocols/ipv6.bpf.c"
#endif

// Helper to check and refresh configuration
// 检查并刷新配置的辅助函数
static __always_inline void check_config_refresh() {
    __u32 key = 0;
    struct stats_global *stats = bpf_map_lookup_elem(&stats_global_map, &key);
    if (stats) {
        // Optimization: No atomic needed for PERCPU_ARRAY
        // 优化：PERCPU_ARRAY 不需要原子操作
        stats->total_packets += 1;
        if (unlikely(stats->total_packets % CONFIG_REFRESH_INTERVAL == 0)) {
            refresh_config();
        }
    }
}

// Helper to parse Ethernet header and handle VLANs
// 解析以太网头并处理 VLAN 的辅助函数
static __always_inline int parse_eth_frame(void *data, void *data_end, void **network_header, __u16 *proto) {
    struct ethhdr *eth = data;
    if (unlikely(data + sizeof(*eth) > data_end)) return -1;

    *network_header = data + sizeof(*eth);
    *proto = eth->h_proto;

    // Handle VLANs (802.1Q and 802.1AD)
    // 处理 VLAN (802.1Q 和 802.1AD)
    if (unlikely(*proto == bpf_htons(ETH_P_8021Q) || *proto == bpf_htons(ETH_P_8021AD))) {
        struct vlan_hdr *vhdr;
        #pragma unroll
        for (int i = 0; i < 2; i++) {
            if (unlikely(*network_header + sizeof(struct vlan_hdr) > data_end)) return -1;
            vhdr = *network_header;
            *proto = vhdr->h_vlan_encapsulated_proto;
            *network_header += sizeof(struct vlan_hdr);
            if (*proto != bpf_htons(ETH_P_8021Q) && *proto != bpf_htons(ETH_P_8021AD)) break;
        }
    }
    return 0;
}

SEC("xdp/ipv4")
int xdp_ipv4(struct xdp_md *ctx) {
    // Check and refresh config
    // 检查并刷新配置
    check_config_refresh();

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    void *network_header;
    __u16 h_proto;
    if (parse_eth_frame(data, data_end, &network_header, &h_proto) < 0) return XDP_PASS;

    // Ensure it is IPv4
    // 确保是 IPv4
    if (h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    int action = handle_ipv4(ctx, data_end, network_header);
    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        update_pass_stats();
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        // Stats are already updated in handle_ipv4/6 with specific reasons
        // 统计信息已在 handle_ipv4/6 中更新了具体原因

        // update_drop_stats(); 
        return XDP_DROP;
    }
    return action;
}

SEC("xdp/ipv6")
int xdp_ipv6(struct xdp_md *ctx) {
#ifdef ENABLE_IPV6
    // Check and refresh config
    check_config_refresh();

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    void *network_header;
    __u16 h_proto;
    if (parse_eth_frame(data, data_end, &network_header, &h_proto) < 0) return XDP_PASS;

    // Ensure it is IPv6
    if (h_proto != bpf_htons(ETH_P_IPV6)) return XDP_PASS;

    int action = handle_ipv6(ctx, data_end, network_header);
    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        update_pass_stats();
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        // Stats are already updated in handle_ipv4/6 with specific reasons
        // update_drop_stats();
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
    // Sample-based configuration refresh to reduce overhead
    // 基于采样的配置刷新以减少开销
    check_config_refresh();

    // Try to call the first plugin slot
    // 尝试调用第一个插件槽位
    // If a plugin is loaded, it's responsible for tail-calling the next plugin or the core logic
    // 如果加载了插件，它负责尾调用下一个插件或核心逻辑
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_PLUGIN_START);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    void *network_header;
    __u16 h_proto;
    if (parse_eth_frame(data, data_end, &network_header, &h_proto) < 0) return XDP_PASS;

    int action = XDP_PASS;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        action = handle_ipv4(ctx, data_end, network_header);
    } 
#ifdef ENABLE_IPV6
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        action = handle_ipv6(ctx, data_end, network_header);
    } 
#endif
    else if (h_proto == bpf_htons(ETH_P_ARP)) {
        return XDP_PASS;
    } else {
        if (cached_strict_proto == 1) {
            update_drop_stats_with_reason(DROP_REASON_PROTOCOL, h_proto, 0, 0);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    // Only update stats if action is PASS or DROP
    // 仅当动作为 PASS 或 DROP 时更新统计信息
    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        update_pass_stats();
    } else if (action == XDP_DROP) {
        // update_drop_stats();
    }

    return action;
}

char _license[] SEC("license") = "GPL";
