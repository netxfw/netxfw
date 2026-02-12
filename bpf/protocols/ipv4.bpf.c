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

static __always_inline int handle_ipv4(struct xdp_md *ctx, void *data_end, void *ip_header) {
    struct iphdr *ip = ip_header;
    if (unlikely((void *)ip + sizeof(*ip) > data_end))
        return XDP_PASS;

    __u16 src_port = 0, dest_port = 0;
    __u8 tcp_flags = 0;
    
    // 0. Sanity Checks & Bogon Filtering
    if (unlikely(cached_bogon_filter == 1)) {
        if (unlikely(is_bogon_ipv4(ip->saddr))) {
            update_drop_stats_with_reason(DROP_REASON_BOGON, ip->protocol, ip->saddr, dest_port);
            return XDP_DROP;
        }
    }

    // Fragmentation check
    if (unlikely(cached_drop_frags == 1)) {
        if (unlikely(bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET))) {
            update_drop_stats_with_reason(DROP_REASON_FRAGMENT, ip->protocol, ip->saddr, dest_port);
            return XDP_DROP;
        }
    }

    // Calculate dynamic IP header length (IHL is in 32-bit words)
    __u32 ip_len = ip->ihl * 4;
    // Sanity check for minimum IP header length
    if (unlikely(ip_len < sizeof(*ip))) {
        update_drop_stats_with_reason(DROP_REASON_BAD_HEADER, ip->protocol, ip->saddr, dest_port);
        return XDP_DROP;
    }

    if (likely(ip->protocol == IPPROTO_TCP)) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if (likely((void *)tcp + sizeof(*tcp) <= data_end)) {
            src_port = bpf_ntohs(tcp->source);
            dest_port = bpf_ntohs(tcp->dest);
            if (likely(tcp->doff >= 5)) {
                tcp_flags = ((__u8 *)tcp)[13];
                // Strict TCP validation
                if (unlikely(cached_strict_tcp == 1)) {
                    if (unlikely(is_invalid_tcp_flags(tcp_flags))) {
                        update_drop_stats_with_reason(DROP_REASON_STRICT_TCP, ip->protocol, ip->saddr, dest_port);
                        return XDP_DROP;
                    }
                } else {
                    // Basic sanity even if strict mode is off
                    if (unlikely(tcp_flags == 0 || (tcp->syn && tcp->fin))) {
                        update_drop_stats_with_reason(DROP_REASON_TCP_FLAGS, ip->protocol, ip->saddr, dest_port);
                        return XDP_DROP;
                    }
                }
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if (likely((void *)udp + sizeof(*udp) <= data_end)) {
            src_port = bpf_ntohs(udp->source);
            dest_port = bpf_ntohs(udp->dest);
        }
    }

    // 0. Anti-Spoofing & Land Attack
    if (unlikely((ip->saddr & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000) || ip->saddr == bpf_htonl(0xffffffff))) {
        update_drop_stats_with_reason(DROP_REASON_SPOOF, ip->protocol, ip->saddr, dest_port);
        return XDP_DROP;
    }
    if (unlikely(is_land_attack_ipv4(ip->saddr, ip->daddr))) {
        update_drop_stats_with_reason(DROP_REASON_LAND_ATTACK, ip->protocol, ip->saddr, dest_port);
        return XDP_DROP;
    }

    // 1. Whitelist
    if (unlikely(is_whitelisted(ip->saddr, dest_port))) {
        update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, ip->saddr, dest_port);
        return XDP_PASS;
    }

    // 2. Lock list
    struct rule_value *cnt = get_blacklist_stats(ip->saddr);
    if (unlikely(cnt)) {
        __sync_fetch_and_add(&cnt->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, ip->protocol, ip->saddr, dest_port);
        return XDP_DROP;
    }

    // 2.5 Rate limit & SYN Flood protection
    if (likely(cached_ratelimit_enabled == 1)) {
        // If it's a SYN packet and SYN limit is enabled, always check rate limit
        // Or if it's just general rate limiting
        int is_syn = (ip->protocol == IPPROTO_TCP && (tcp_flags & 0x02));
        
        if (likely(cached_syn_limit == 0 || is_syn)) {
            if (unlikely(!check_ratelimit(ip->saddr))) {
                update_drop_stats_with_reason(DROP_REASON_RATELIMIT, ip->protocol, ip->saddr, dest_port);
                return XDP_DROP;
            }
        }
    }

    // 3. Conntrack
    if (likely(cached_ct_enabled == 1)) {
        struct ct_key look_key = {
            .src_ip = ip->daddr, .dst_ip = ip->saddr,
            .src_port = dest_port, .dst_port = src_port,
            .protocol = ip->protocol,
        };
        struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &look_key);
        if (likely(ct_val && (bpf_ktime_get_ns() - ct_val->last_seen < cached_ct_timeout))) {
            update_pass_stats_with_reason(PASS_REASON_CONNTRACK, ip->protocol, ip->saddr, dest_port);
            return XDP_PASS;
        }
    }

    // 4. IP+Port rules
    if (dest_port > 0) {
        int rule_action = check_ip_port_rule(ip->saddr, dest_port);
        if (unlikely(rule_action == 1)) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, ip->saddr, dest_port);
            return XDP_PASS;
        }
        if (unlikely(rule_action == 2)) {
            update_drop_stats_with_reason(DROP_REASON_BLACKLIST, ip->protocol, ip->saddr, dest_port);
            return XDP_DROP;
        }
    }

    // 5. ICMP
    if (unlikely(ip->protocol == IPPROTO_ICMP && cached_allow_icmp == 1)) {
        if (likely(check_icmp_limit(cached_icmp_rate, cached_icmp_burst))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, ip->saddr, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_RATELIMIT, ip->protocol, ip->saddr, dest_port);
        return XDP_DROP;
    }

    // 6. Return traffic
    if (unlikely(cached_allow_return == 1 && cached_ct_enabled == 0)) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end && tcp->ack && dest_port >= 32768) {
                update_pass_stats_with_reason(PASS_REASON_RETURN, ip->protocol, ip->saddr, dest_port);
                return XDP_PASS;
            }
        } else if (ip->protocol == IPPROTO_UDP && dest_port >= 32768) {
            update_pass_stats_with_reason(PASS_REASON_RETURN, ip->protocol, ip->saddr, dest_port);
            return XDP_PASS;
        }
    }

    // 7. Default Deny / Port Whitelist
    if (likely(dest_port > 0 && cached_default_deny == 1)) {
        if (likely(bpf_map_lookup_elem(&allowed_ports, &dest_port))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, ip->saddr, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_DEFAULT, ip->protocol, ip->saddr, dest_port);
        return XDP_DROP;
    }

    update_pass_stats_with_reason(PASS_REASON_DEFAULT, ip->protocol, ip->saddr, dest_port);
    return XDP_PASS;
}

#endif // __NETXFW_IPV4_BPF_C
