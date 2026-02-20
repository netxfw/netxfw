// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __NETXFW_PLUGIN_H
#define __NETXFW_PLUGIN_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "protocol.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"

/**
 * Plugin return codes
 * 插件返回值
 */
#define PLUGIN_PASS      XDP_PASS
#define PLUGIN_DROP      XDP_DROP
#define PLUGIN_ABORT     XDP_ABORTED

/**
 * Helper to continue to the next plugin or core logic
 * 继续执行后续插件或核心逻辑的辅助函数
 */
static __always_inline void netxfw_plugin_continue(struct xdp_md *ctx) {
    // For now, we jump directly to the protocol handlers
    // Currently, we don't support chaining plugins automatically via this helper 
    // without more complex logic. 
    // Simple approach: Jump to the core firewall logic entry point
    // 目前，我们直接跳转到协议处理程序
    // 当前，如果不使用更复杂的逻辑，我们不支持通过此辅助函数自动链接插件。
    // 简单方法：跳转到核心防火墙逻辑入口点
    struct ethhdr *eth = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if ((void *)(eth + 1) > data_end) return;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        bpf_tail_call(ctx, &jmp_table, PROG_IDX_IPV4);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_tail_call(ctx, &jmp_table, PROG_IDX_IPV6);
    }
}

/**
 * Macro to define a plugin entry point
 * 定义插件入口的宏
 */
#define NETXFW_PLUGIN(name) \
    SEC("xdp/plugin_" #name) \
    int netxfw_plugin_##name(struct xdp_md *ctx)

#endif // __NETXFW_PLUGIN_H
