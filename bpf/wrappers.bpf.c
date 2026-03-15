// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
#include "include/protocol.h"
#include "include/maps.bpf.h"
#include "include/helpers.bpf.h"
#include "include/config.bpf.h"

// Include modules (guards ensure single inclusion)
#include "modules/blacklist.bpf.c"
#include "modules/filter.bpf.c"
#include "modules/ratelimit.bpf.c"
#include "modules/rules.bpf.c"
#include "modules/icmp.bpf.c"
#include "modules/conntrack.bpf.c"
#include "modules/stats.bpf.c"

// Helper to tail call next module
static __always_inline int tail_call_next(struct xdp_md *ctx, __u32 current_mod_id) {
    __u32 key = current_mod_id;
    __u32 *next_prog_idx = bpf_map_lookup_elem(&chain_map, &key);
    if (next_prog_idx) {
        bpf_tail_call(ctx, &jmp_table, *next_prog_idx);
    }
    return XDP_PASS;
}

// Helper to parse common packet info
static __always_inline int parse_packet_info(struct xdp_md *ctx, void **data_end_ptr, struct iphdr **ip_ptr, struct in6_addr *src_ip6, __u16 *dest_port, __u8 *protocol, __u8 *tcp_flags) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    *data_end_ptr = data_end;
    *ip_ptr = 0;

    struct ethhdr *eth = data;
    if (unlikely(data + sizeof(*eth) > data_end)) return -1;

    __u16 h_proto = eth->h_proto;
    void *network_header = data + sizeof(*eth);

    // Handle VLANs
    if (unlikely(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))) {
        struct vlan_hdr *vhdr;
        #pragma unroll
        for (int i = 0; i < 2; i++) {
            if (unlikely(network_header + sizeof(struct vlan_hdr) > data_end)) return -1;
            vhdr = network_header;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            network_header += sizeof(struct vlan_hdr);
            if (h_proto != bpf_htons(ETH_P_8021Q) && h_proto != bpf_htons(ETH_P_8021AD)) break;
        }
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = network_header;
        if (unlikely((void *)ip + sizeof(*ip) > data_end)) return -1;
        *ip_ptr = ip;
        *protocol = ip->protocol;

        // Convert to IPv6-mapped
        ipv4_to_ipv6_mapped(ip->saddr, src_ip6);

        __u32 ip_len = ip->ihl * 4;
        if (unlikely(ip_len < sizeof(*ip))) return -1;

        if (*protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ip_len;
            if (likely((void *)tcp + sizeof(*tcp) <= data_end)) {
                *dest_port = bpf_ntohs(tcp->dest);
                if (likely(tcp->doff >= 5)) {
                    *tcp_flags = ((__u8 *)tcp)[13];
                }
            }
        } else if (*protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip_len;
            if (likely((void *)udp + sizeof(*udp) <= data_end)) {
                *dest_port = bpf_ntohs(udp->dest);
            }
        }
        return 0;
    }
    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = network_header;
        if (unlikely((void *)ip6 + sizeof(*ip6) > data_end)) return -1;
        *protocol = ip6->nexthdr;
        *src_ip6 = ip6->saddr;

        void *cur_header = (void *)ip6 + sizeof(*ip6);
        __u8 next_proto = *protocol;

        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (unlikely(cur_header + 2 > data_end)) return -1;
            if (next_proto == IPPROTO_TCP || next_proto == IPPROTO_UDP) break;

            if (next_proto == IPPROTO_HOPOPTS || next_proto == IPPROTO_ROUTING ||
                next_proto == IPPROTO_DSTOPTS || next_proto == IPPROTO_AH) {
                __u8 *hdr_ptr = cur_header;
                next_proto = *hdr_ptr;
                __u8 len_val = *(hdr_ptr + 1);
                int ext_len = (len_val + 1) * 8;
                if (unlikely(cur_header + ext_len > data_end)) return -1;
                cur_header += ext_len;
            } else if (next_proto == IPPROTO_FRAGMENT) {
                if (unlikely(cur_header + 8 > data_end)) return -1;
                struct ipv6_frag_hdr *frag = cur_header;
                next_proto = frag->nexthdr;
                if (bpf_ntohs(frag->frag_off) & 0xfff8) {
                    *protocol = next_proto;
                    return 1;
                }
                cur_header += 8;
            } else {
                break;
            }
        }

        *protocol = next_proto;
        if (next_proto == IPPROTO_TCP) {
            struct tcphdr *tcp = cur_header;
            if (likely((void *)tcp + sizeof(*tcp) <= data_end)) {
                *dest_port = bpf_ntohs(tcp->dest);
                if (likely(tcp->doff >= 5)) {
                    *tcp_flags = ((__u8 *)tcp)[13];
                }
            }
        } else if (next_proto == IPPROTO_UDP) {
            struct udphdr *udp = cur_header;
            if (likely((void *)udp + sizeof(*udp) <= data_end)) {
                *dest_port = bpf_ntohs(udp->dest);
            }
        }
        return 1;
    }
    return -2;
}

SEC("xdp/sanity")
int xdp_sanity(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    int ret = parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags);
    if (ret < 0) return XDP_PASS;
    if (ret != 0) return tail_call_next(ctx, MOD_ID_SANITY);

    // Bogon Filter
    if (unlikely(cached_bogon_filter == 1)) {
        if (unlikely(is_bogon_ipv4(ip->saddr))) {
            update_drop_stats_with_reason(DROP_REASON_BOGON, protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    // Fragmentation check
    if (unlikely(cached_drop_frags == 1)) {
        if (unlikely(bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET))) {
            update_drop_stats_with_reason(DROP_REASON_FRAGMENT, protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    // Strict TCP
    if (protocol == IPPROTO_TCP && unlikely(cached_strict_tcp == 1)) {
         if (unlikely(is_invalid_tcp_flags(tcp_flags))) {
            update_drop_stats_with_reason(DROP_REASON_STRICT_TCP, protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    // Anti-Spoofing & Land Attack
    if (unlikely((ip->saddr & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000) || ip->saddr == bpf_htonl(0xffffffff))) {
        update_drop_stats_with_reason(DROP_REASON_SPOOF, protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }
    if (unlikely(is_land_attack_ipv4(ip->saddr, ip->daddr))) {
        update_drop_stats_with_reason(DROP_REASON_LAND_ATTACK, protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    return tail_call_next(ctx, MOD_ID_SANITY);
}

SEC("xdp/critical")
int xdp_critical(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    struct rule_value *critical = bpf_map_lookup_elem(&critical_blacklist, &src_ip6);
    if (unlikely(critical)) {
        __sync_fetch_and_add(&critical->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    return tail_call_next(ctx, MOD_ID_CRITICAL);
}

SEC("xdp/whitelist")
int xdp_whitelist(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    if (unlikely(is_whitelisted(&src_ip6, dest_port))) {
        update_pass_stats_with_reason(PASS_REASON_WHITELIST, protocol, &src_ip6, dest_port);
        return XDP_PASS; // Whitelist means ACCEPT, stop processing?
        // Usually whitelist bypasses other checks. So XDP_PASS (accept) is correct.
        // We do NOT tail call next.
    }

    return tail_call_next(ctx, MOD_ID_WHITELIST);
}

SEC("xdp/blacklist")
int xdp_blacklist(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    // Check static blacklist (LPM)
    // 检查静态黑名单 (LPM)
    struct rule_value *cnt = check_static_blacklist(&src_ip6);
    if (unlikely(cnt)) {
        __sync_fetch_and_add(&cnt->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    return tail_call_next(ctx, MOD_ID_BLACKLIST);
}

SEC("xdp/dynamic_blacklist")
int xdp_dynamic_blacklist(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    // Check dynamic blacklist (LRU)
    // 检查动态黑名单 (LRU)
    struct rule_value *cnt = check_dynamic_blacklist(&src_ip6);
    if (unlikely(cnt)) {
        __sync_fetch_and_add(&cnt->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    return tail_call_next(ctx, MOD_ID_DYNAMIC_BLACKLIST);
}

SEC("xdp/ratelimit")
int xdp_ratelimit(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    if (likely(cached_ratelimit_enabled == 1)) {
        int is_syn = (protocol == IPPROTO_TCP && (tcp_flags & 0x02));
        if (likely(cached_syn_limit == 0 || is_syn)) {
            if (unlikely(!check_ratelimit(&src_ip6))) {
                update_drop_stats_with_reason(DROP_REASON_RATELIMIT, protocol, &src_ip6, dest_port);
                return XDP_DROP;
            }
        }
    }

    return tail_call_next(ctx, MOD_ID_RATELIMIT);
}

SEC("xdp/conntrack")
int xdp_conntrack(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    int ret = parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags);
    if (ret < 0) return XDP_PASS;

    if (likely(cached_ct_enabled == 1)) {
        if (ret != 0) return tail_call_next(ctx, MOD_ID_CONNTRACK);
        struct in6_addr dst_ip6 = {};
        ipv4_to_ipv6_mapped(ip->daddr, &dst_ip6);

        __u16 src_port = 0;
        // Need source port for conntrack lookup
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
             if ((void *)tcp + sizeof(*tcp) <= data_end) src_port = bpf_ntohs(tcp->source);
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
             if ((void *)udp + sizeof(*udp) <= data_end) src_port = bpf_ntohs(udp->source);
        }

        struct ct_key look_key = {
            .src_ip = dst_ip6,
            .dst_ip = src_ip6,
            .src_port = dest_port,
            .dst_port = src_port,
            .protocol = protocol,
        };
        struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &look_key);
        if (likely(ct_val && (bpf_ktime_get_ns() - ct_val->last_seen < cached_ct_timeout))) {
            update_pass_stats_with_reason(PASS_REASON_CONNTRACK, protocol, &src_ip6, dest_port);
            return XDP_PASS; // Established connection -> Pass
        }
    }

    return tail_call_next(ctx, MOD_ID_CONNTRACK);
}

SEC("xdp/rules")
int xdp_rules(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    if (dest_port > 0) {
        int rule_action = check_ip_port_rule(&src_ip6, dest_port);
        if (unlikely(rule_action == 1)) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
        if (unlikely(rule_action == 0)) {
            update_drop_stats_with_reason(DROP_REASON_BLACKLIST, protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    return tail_call_next(ctx, MOD_ID_RULES);
}

SEC("xdp/icmp")
int xdp_icmp(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    if (unlikely(protocol == IPPROTO_ICMP && cached_allow_icmp == 1)) {
        if (likely(check_icmp_limit(cached_icmp_rate, cached_icmp_burst))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_RATELIMIT, protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    return tail_call_next(ctx, MOD_ID_ICMP);
}

SEC("xdp/return")
int xdp_return(struct xdp_md *ctx) {
    void *data_end;
    struct iphdr *ip;
    struct in6_addr src_ip6 = {};
    __u16 dest_port = 0;
    __u8 protocol = 0;
    __u8 tcp_flags = 0;

    if (parse_packet_info(ctx, &data_end, &ip, &src_ip6, &dest_port, &protocol, &tcp_flags) < 0) return XDP_PASS;

    if (unlikely(cached_allow_return == 1)) {
        if (protocol == IPPROTO_TCP) {
            if (tcp_flags & 0x10) {
                update_pass_stats_with_reason(PASS_REASON_RETURN, protocol, &src_ip6, dest_port);
                return XDP_PASS;
            }
        } else if (protocol == IPPROTO_UDP) {
            update_pass_stats_with_reason(PASS_REASON_RETURN, protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
    }

    return tail_call_next(ctx, MOD_ID_RETURN);
}
