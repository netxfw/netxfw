// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
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
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_MAIN);
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_DEFAULT_DENY);
}

/**
 * Macro to define a plugin entry point
 * 定义插件入口的宏
 */
#define NETXFW_PLUGIN(name) \
    SEC("xdp/plugin_" #name) \
    int netxfw_plugin_##name(struct xdp_md *ctx)

#endif // __NETXFW_PLUGIN_H
