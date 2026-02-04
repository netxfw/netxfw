// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#include "include/protocol.h"
#include "include/maps.bpf.h"
#include "include/helpers.bpf.h"
#include "include/config.bpf.h"
#include "protocols/ipv4.bpf.c"
#include "protocols/ipv6.bpf.c"

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
    int action = XDP_PASS;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        refresh_config();
        action = handle_ipv4(ctx, data, data_end, eth);
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        refresh_config();
        action = handle_ipv6(ctx, data, data_end, eth);
    } else if (h_proto == bpf_htons(ETH_P_ARP)) {
        return XDP_PASS;
    } else {
        refresh_config();
        if (cached_strict_proto == 1) {
            action = XDP_DROP;
        } else {
            return XDP_PASS;
        }
    }

    if (action == XDP_PASS) {
        if (cached_af_xdp_enabled == 1) {
            return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        }
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&pass_stats, &key);
        if (count) *count += 1;
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
        if (count) *count += 1;
        return XDP_DROP;
    }

    return action;
}

SEC("classifier")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u32 key = CONFIG_ENABLE_CONNTRACK;
    __u32 *enabled = bpf_map_lookup_elem(&global_config, &key);
    if (!enabled || *enabled != 1) return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0, protocol = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_OK;
        protocol = ip->protocol;
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + sizeof(*ip);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
        if (src_port == 0 || dst_port == 0) return TC_ACT_OK;
        struct ct_key ct_key = { .src_ip = ip->saddr, .dst_ip = ip->daddr, .src_port = src_port, .dst_port = dst_port, .protocol = protocol };
        if (protocol == IPPROTO_TCP) {
            if (tcp_flags & 1) {
                struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
                bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
            } else {
                struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map, &ct_key);
                if (exists) exists->last_seen = bpf_ktime_get_ns();
            }
        } else {
            struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
            bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_OK;
        protocol = ip6->nexthdr;
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip6 + sizeof(*ip6);
            if ((void *)udp + sizeof(*udp) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
        if (src_port == 0 || dst_port == 0) return TC_ACT_OK;
        struct ct_key6 ct_key = { .src_ip = ip6->saddr, .dst_ip = ip6->daddr, .src_port = src_port, .dst_port = dst_port, .protocol = protocol };
        if (protocol == IPPROTO_TCP) {
            if (tcp_flags & 1) {
                struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
                bpf_map_update_elem(&conntrack_map6, &ct_key, &ct_val, BPF_ANY);
            } else {
                struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map6, &ct_key);
                if (exists) exists->last_seen = bpf_ktime_get_ns();
            }
        } else {
            struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
            bpf_map_update_elem(&conntrack_map6, &ct_key, &ct_val, BPF_ANY);
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
