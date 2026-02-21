// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
#include "../include/plugin.h"

/**
 * Example plugin: Drops all traffic from a specific test IP
 * 示例插件：丢弃来自特定测试 IP 的所有流量
 */
NETXFW_PLUGIN(example_filter) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        netxfw_plugin_continue(ctx);
        return PLUGIN_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
            netxfw_plugin_continue(ctx);
            return PLUGIN_PASS;
        }

        // Example: Drop traffic from 1.2.3.4 (hex: 0x04030201 in network byte order)
        // 示例：丢弃来自 1.2.3.4 的流量
        if (ip->saddr == 0x04030201) {
            return PLUGIN_DROP;
        }
    }

    netxfw_plugin_continue(ctx);
    return PLUGIN_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
