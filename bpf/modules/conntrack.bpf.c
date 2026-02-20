// SPDX-License-Identifier: GPL-2.0-or-later
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
    if (unlikely(!enabled || *enabled != 1)) return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (unlikely(data + sizeof(*eth) > data_end)) return TC_ACT_OK;

    // Handle VLANs
    // 处理 VLAN
    __u16 h_proto = eth->h_proto;
    void *network_header = data + sizeof(*eth);
    
    if (unlikely(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))) {
        struct vlan_hdr *vhdr;
        #pragma unroll
        for (int i = 0; i < 2; i++) {
            if (unlikely(network_header + sizeof(struct vlan_hdr) > data_end)) return TC_ACT_OK;
            vhdr = network_header;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            network_header += sizeof(struct vlan_hdr);
            if (h_proto != bpf_htons(ETH_P_8021Q) && h_proto != bpf_htons(ETH_P_8021AD)) break;
        }
    }

    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0, protocol = 0;

    if (likely(h_proto == bpf_htons(ETH_P_IP))) {
        struct iphdr *ip = network_header;
        if (unlikely((void *)ip + sizeof(*ip) > data_end)) return TC_ACT_OK;
        
        // Dynamic IP header length
        // 动态 IP 头长度
        __u32 ip_len = ip->ihl * 4;
        if (unlikely(ip_len < sizeof(*ip))) return TC_ACT_OK;
        
        protocol = ip->protocol;
        if (likely(protocol == IPPROTO_TCP)) {
            struct tcphdr *tcp = (void *)ip + ip_len;
            if (likely((void *)tcp + sizeof(*tcp) <= data_end)) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip_len;
            if (likely((void *)udp + sizeof(*udp) <= data_end)) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
        if (unlikely(src_port == 0 || dst_port == 0)) return TC_ACT_OK;

        struct ct_key ct_key = { 
            .src_port = src_port, 
            .dst_port = dst_port, 
            .protocol = protocol 
        };
        ipv4_to_ipv6_mapped(ip->saddr, &ct_key.src_ip);
        ipv4_to_ipv6_mapped(ip->daddr, &ct_key.dst_ip);

        if (likely(protocol == IPPROTO_TCP)) {
            if (tcp_flags & 1) {
                struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
                bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
            } else {
                struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map, &ct_key);
                if (likely(exists)) {
                    __u64 now = bpf_ktime_get_ns();
                    // Optimization: Only update if >1s has passed to reduce cache thrashing
                    // 优化：仅在超过 1 秒时更新，以减少缓存抖动
                    if (now - exists->last_seen > 1000000000) {
                        exists->last_seen = now;
                    }
                }
            }
        } else {
            // For UDP/ICMP, we can also optimize lookup before update?
            // But standard behavior is update to refresh LRU.
            // Let's try to lookup first? No, direct update is cleaner for LRU.
            // But we can check if it exists to avoid full update overhead?
            // 对于 UDP/ICMP，我们也可以在更新前优化查找吗？
            // 但标准行为是更新以刷新 LRU。
            // 让我们先尝试查找？不，直接更新对于 LRU 更清晰。
            // 但我们可以检查它是否存在以避免完全更新的开销？

            // Let's stick to update for now, or apply same optimization?
            // UDP is stateless, so every packet renews.
            struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map, &ct_key);
            __u64 now = bpf_ktime_get_ns();
            if (exists) {
                if (now - exists->last_seen > 1000000000) {
                     exists->last_seen = now;
                }
            } else {
                struct ct_value ct_val = { .last_seen = now };
                bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
            }
        }
#ifdef ENABLE_IPV6
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = network_header;
        if (unlikely((void *)ip6 + sizeof(*ip6) > data_end)) return TC_ACT_OK;
        
        protocol = ip6->nexthdr;
        void *cur_header = (void *)ip6 + sizeof(*ip6);
        
        // Skip IPv6 extension headers
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (unlikely(cur_header + 2 > data_end)) break;
            if (likely(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)) break;
            
            if (protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_ROUTING || 
                protocol == IPPROTO_DSTOPTS || protocol == IPPROTO_AH) {
                __u8 *hdr_ptr = cur_header;
                protocol = *hdr_ptr;
                __u8 len_val = *(hdr_ptr + 1);
                int ext_len = (len_val + 1) * 8;
                if (unlikely(cur_header + ext_len > data_end)) return TC_ACT_OK;
                cur_header += ext_len;
            } else if (protocol == IPPROTO_FRAGMENT) {
                if (unlikely(cur_header + 8 > data_end)) return TC_ACT_OK;
                struct ipv6_frag_hdr {
                     __u8    nexthdr;
                     __u8    reserved;
                     __be16  frag_off;
                     __be32  identification;
                } *frag = cur_header;
                if (unlikely((frag->frag_off & bpf_htons(0xFFF9)) != 0)) return TC_ACT_OK;
                protocol = frag->nexthdr;
                cur_header += 8;
            } else {
                break;
            }
        }

        if (likely(protocol == IPPROTO_TCP)) {
            struct tcphdr *tcp = cur_header;
            if (likely((void *)tcp + sizeof(*tcp) <= data_end)) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = cur_header;
            if (likely((void *)udp + sizeof(*udp) <= data_end)) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
        
        if (unlikely(src_port == 0 || dst_port == 0)) return TC_ACT_OK;
        
        struct ct_key ct_key = { 
            .src_ip = ip6->saddr, .dst_ip = ip6->daddr, 
            .src_port = src_port, .dst_port = dst_port, 
            .protocol = protocol 
        };
        
        if (likely(protocol == IPPROTO_TCP)) {
            if (tcp_flags & 1) {
                 struct ct_value ct_val = { .last_seen = bpf_ktime_get_ns() };
                 bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
            } else {
                 struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map, &ct_key);
                 if (likely(exists)) {
                     __u64 now = bpf_ktime_get_ns();
                     if (now - exists->last_seen > 1000000000) {
                         exists->last_seen = now;
                     }
                 }
            }
        } else {
             struct ct_value *exists = bpf_map_lookup_elem(&conntrack_map, &ct_key);
             __u64 now = bpf_ktime_get_ns();
             if (exists) {
                 if (now - exists->last_seen > 1000000000) {
                     exists->last_seen = now;
                 }
             } else {
                 struct ct_value ct_val = { .last_seen = now };
                 bpf_map_update_elem(&conntrack_map, &ct_key, &ct_val, BPF_ANY);
             }
        }
#endif
    }
    return TC_ACT_OK;
}

#endif // __NETXFW_CONNTRACK_BPF_C
