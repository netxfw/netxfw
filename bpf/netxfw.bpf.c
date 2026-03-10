// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
/*
 * NetXfw BPF Program - Kernel Space XDP Firewall
 *
 * This BPF program is dual-licensed under BSD-2-Clause OR GPL-2.0-only.
 * The GPL license is required for kernel compatibility with GPL-only helper functions.
 * The BSD license option is available for users who prefer more permissive terms.
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
        // Bitwise optimization: interval must be a power of 2
        // 位运算优化：间隔必须是 2 的幂
        if (unlikely((stats->total_packets & (CONFIG_REFRESH_INTERVAL - 1)) == 0)) {
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
    // This section is now the MAIN program (Slot 1)
    // 此部分现在是主程序（插槽 1）

    // Check and refresh config
    // 检查并刷新配置
    check_config_refresh();

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

    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        update_pass_stats();
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        // Stats are already updated in handle_ipv4/6 with specific reasons
        // 统计信息已在 handle_ipv4/6 中更新了具体原因
        return XDP_DROP;
    }
    return action;
}

SEC("xdp/ipv6")
int xdp_ipv6(struct xdp_md *ctx) {
    // This section is now the DEFAULT DENY program (Slot 15)
    // 此部分现在是默认拒绝程序（插槽 15）

    // Update stats for default deny
    // 更新默认拒绝统计信息
    __u32 key = 0;
    struct stats_global *stats = bpf_map_lookup_elem(&stats_global_map, &key);
    if (stats) {
        stats->total_drop += 1;
        stats->drop_default_deny += 1;
    }

    // Simple drop logic as a safety net
    // 简单的丢弃逻辑作为安全网
    return XDP_DROP;
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

    // 1. Try to jump to the configured chain start (Dynamic Modules)
    // 1. 尝试跳转到配置的链起点（动态模块）
    // Usually chain starts at index 20+
    __u32 key = MOD_ID_ENTRY;
    __u32 *start_idx = bpf_map_lookup_elem(&chain_map, &key);
    if (start_idx) {
        bpf_tail_call(ctx, &jmp_table, *start_idx);
    }

    // 2. Try to call the first plugin slot (Slot 2)
    // 2. 尝试调用第一个插件槽位（插槽 2）
    // If a plugin exists, it executes. If it fails (empty slot), we fall through.
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_PLUGIN_START);

    // 3. Fallback to Main Program (Slot 1) if plugins didn't handle it
    // 3. 如果插件未处理，则回退到主程序（插槽 1）
    // Note: If plugins want to continue to Main, they must explicitly tail_call(1) or return XDP_PASS (but tail_call doesn't return)
    // 注意：如果插件想要继续执行主程序，它们必须显式调用 tail_call(1)
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_MAIN);

    // 4. Ultimate Safety Net: Default Deny (Slot 15)
    // 4. 终极安全网：默认拒绝（插槽 15）
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_DEFAULT_DENY);

    // 5. Hard Drop if everything fails
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual BSD/GPL";

// Include dynamic module wrappers
// 包含动态模块封装
#include "wrappers.bpf.c"
