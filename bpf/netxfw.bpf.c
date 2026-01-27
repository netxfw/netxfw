// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr);
    __type(value, __u64);
} blacklist6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

static inline int is_blocked(__u32 ip) {
    __u64 *val = bpf_map_lookup_elem(&blacklist, &ip);
    return val != NULL;
}

static inline int is_blocked6(struct in6_addr *ip) {
    __u64 *val = bpf_map_lookup_elem(&blacklist6, ip);
    return val != NULL;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        if (is_blocked(ip->saddr)) {
            __u64 *cnt = bpf_map_lookup_elem(&blacklist, &ip->saddr);
            if (cnt) {
                __sync_fetch_and_add(cnt, 1);
            }

            __u32 key = 0;
            __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
            if (count) {
                *count += 1;
            }
            return XDP_DROP;
        }
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
            return XDP_PASS;

        if (is_blocked6(&ip6->saddr)) {
            __u64 *cnt = bpf_map_lookup_elem(&blacklist6, &ip6->saddr);
            if (cnt) {
                __sync_fetch_and_add(cnt, 1);
            }

            __u32 key = 0;
            __u64 *count = bpf_map_lookup_elem(&drop_stats, &key);
            if (count) {
                *count += 1;
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";