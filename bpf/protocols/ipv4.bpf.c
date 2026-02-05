// SPDX-License-Identifier: MIT
#ifndef __NETXFW_IPV4_BPF_C
#define __NETXFW_IPV4_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"
#include "../include/config.bpf.h"

// Include necessary modules
#include "../modules/blacklist.bpf.c"
#include "../modules/filter.bpf.c"
#include "../modules/ratelimit.bpf.c"
#include "../modules/rules.bpf.c"
#include "../modules/icmp.bpf.c"

static __always_inline int handle_ipv4(struct xdp_md *ctx, void *data, void *data_end, struct ethhdr *eth) {
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dest_port = 0;
    __u8 tcp_flags = 0;
    
    // 0. Sanity Checks & Bogon Filtering
    if (cached_bogon_filter == 1) {
        if (is_bogon_ipv4(ip->saddr)) {
            return XDP_DROP;
        }
    }

    // Fragmentation check
    if (cached_drop_frags == 1) {
        if (bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET)) {
            return XDP_DROP;
        }
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dest_port = bpf_ntohs(tcp->dest);
            if (tcp->doff >= 5) {
                tcp_flags = ((__u8 *)tcp)[13];
                // Strict TCP validation
                if (cached_strict_tcp == 1) {
                    if (is_invalid_tcp_flags(tcp_flags)) {
                        return XDP_DROP;
                    }
                } else {
                    // Basic sanity even if strict mode is off
                    if (tcp_flags == 0 || (tcp->syn && tcp->fin)) {
                        return XDP_DROP;
                    }
                }
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dest_port = bpf_ntohs(udp->dest);
        }
    }

    // 0. Anti-Spoofing
    if ((ip->saddr & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000) || ip->saddr == bpf_htonl(0xffffffff)) {
        return XDP_DROP;
    }

    // 1. Whitelist
    if (is_whitelisted(ip->saddr, dest_port)) {
        return XDP_PASS;
    }

    // 2. Lock list
    struct rule_value *cnt = get_blacklist_stats(ip->saddr);
    if (cnt) {
        __sync_fetch_and_add(&cnt->counter, 1);
        return XDP_DROP;
    }

    // 2.5 Rate limit & SYN Flood protection
    if (cached_ratelimit_enabled == 1) {
        // If it's a SYN packet and SYN limit is enabled, always check rate limit
        // Or if it's just general rate limiting
        int is_syn = (ip->protocol == IPPROTO_TCP && (tcp_flags & 0x02));
        
        if (cached_syn_limit == 0 || is_syn) {
            if (!check_ratelimit(ip->saddr)) {
                return XDP_DROP;
            }
        }
    }

    // 3. Conntrack
    if (cached_ct_enabled == 1) {
        struct ct_key look_key = {
            .src_ip = ip->daddr, .dst_ip = ip->saddr,
            .src_port = dest_port, .dst_port = src_port,
            .protocol = ip->protocol,
        };
        struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &look_key);
        if (ct_val && (bpf_ktime_get_ns() - ct_val->last_seen < cached_ct_timeout)) {
            return XDP_PASS;
        }
    }

    // 4. IP+Port rules
    if (dest_port > 0) {
        int rule_action = check_ip_port_rule(ip->saddr, dest_port);
        if (rule_action == 1) return XDP_PASS;
        if (rule_action == 2) return XDP_DROP;
    }

    // 5. ICMP
    if (ip->protocol == IPPROTO_ICMP && cached_allow_icmp == 1) {
        if (check_icmp_limit(cached_icmp_rate, cached_icmp_burst)) {
            return XDP_PASS;
        }
        return XDP_DROP;
    }

    // 6. Return traffic
    if (cached_allow_return == 1 && cached_ct_enabled == 0) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end && tcp->ack && dest_port >= 32768) {
                return XDP_PASS;
            }
        } else if (ip->protocol == IPPROTO_UDP && dest_port >= 32768) {
            return XDP_PASS;
        }
    }

    // 7. Default Deny / Port Whitelist
    if (dest_port > 0 && cached_default_deny == 1) {
        if (bpf_map_lookup_elem(&allowed_ports, &dest_port)) {
            return XDP_PASS;
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif // __NETXFW_IPV4_BPF_C
