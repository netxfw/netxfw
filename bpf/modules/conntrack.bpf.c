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

    // Handle VLANs
    __u16 h_proto = eth->h_proto;
    void *network_header = data + sizeof(*eth);
    
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        #pragma unroll
        for (int i = 0; i < 2; i++) {
            if (network_header + sizeof(struct vlan_hdr) > data_end) return TC_ACT_OK;
            vhdr = network_header;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            network_header += sizeof(struct vlan_hdr);
            if (h_proto != bpf_htons(ETH_P_8021Q) && h_proto != bpf_htons(ETH_P_8021AD)) break;
        }
    }

    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0, protocol = 0;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = network_header;
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;
        
        // Dynamic IP header length
        __u32 ip_len = ip->ihl * 4;
        if (ip_len < sizeof(*ip)) return TC_ACT_OK;
        
        protocol = ip->protocol;
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ip_len;
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip_len;
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
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = network_header;
        if ((void *)ip6 + sizeof(*ip6) > data_end) return TC_ACT_OK;
        
        protocol = ip6->nexthdr;
        void *cur_header = (void *)ip6 + sizeof(*ip6);
        
        // Skip IPv6 extension headers
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (cur_header + 2 > data_end) break;
            if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) break;
            
            if (protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_ROUTING || 
                protocol == IPPROTO_DSTOPTS || protocol == IPPROTO_AH) {
                __u8 *hdr_ptr = cur_header;
                protocol = *hdr_ptr;
                __u8 len_val = *(hdr_ptr + 1);
                int ext_len = (len_val + 1) * 8;
                if (cur_header + ext_len > data_end) return TC_ACT_OK;
                cur_header += ext_len;
            } else if (protocol == IPPROTO_FRAGMENT) {
                if (cur_header + 8 > data_end) return TC_ACT_OK;
                // Cannot track fragmented packets effectively in simple CT
                return TC_ACT_OK;
            } else {
                break;
            }
        }

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = cur_header;
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                if (tcp->syn) tcp_flags |= 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = cur_header;
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
