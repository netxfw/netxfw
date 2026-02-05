// SPDX-License-Identifier: MIT
#ifndef __NETXFW_CONNTRACK_BPF_C
#define __NETXFW_CONNTRACK_BPF_C

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"

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
#ifdef ENABLE_IPV6
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
#endif
    }
    return TC_ACT_OK;
}

#endif // __NETXFW_CONNTRACK_BPF_C
