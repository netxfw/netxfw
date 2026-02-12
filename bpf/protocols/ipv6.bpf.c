// SPDX-License-Identifier: MIT
#ifndef __NETXFW_IPV6_BPF_C
#define __NETXFW_IPV6_BPF_C

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

static __always_inline int handle_ipv6(struct xdp_md *ctx, void *data_end, void *ip_header) {
    struct ipv6hdr *ip6 = ip_header;
    if ((void *)ip6 + sizeof(*ip6) > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dest_port = 0;
    __u8 tcp_flags = 0;
    __u8 next_proto = ip6->nexthdr;
    void *cur_header = (void *)ip6 + sizeof(*ip6);

    // Skip IPv6 extension headers
    #pragma unroll
    for (int i = 0; i < 4; i++) { // Limit loop to prevent DoS/verifier issues
        if (cur_header + 2 > data_end) break; // Need at least 2 bytes for next header

        if (next_proto == IPPROTO_TCP || next_proto == IPPROTO_UDP) break;
        
        // Check for known extension headers
        if (next_proto == IPPROTO_HOPOPTS || next_proto == IPPROTO_ROUTING || 
            next_proto == IPPROTO_DSTOPTS || next_proto == IPPROTO_AH) {
            
            // Ext header format: [Next Header (1B)][Hdr Ext Len (1B)][...payload...]
            // Length is in 8-octet units, not including the first 8 octets
            __u8 *hdr_ptr = cur_header;
            next_proto = *hdr_ptr;
            __u8 len_val = *(hdr_ptr + 1);
            
            // RFC 2460: Length field is in 8-octet units, excluding the first 8 octets
            // Actual length = (len_val + 1) * 8
            int ext_len = (len_val + 1) * 8;
            
            if (cur_header + ext_len > data_end) return XDP_PASS; // Malformed
            cur_header += ext_len;
        } else if (next_proto == IPPROTO_FRAGMENT) {
            // Fragment header is fixed 8 bytes
            if (cur_header + 8 > data_end) return XDP_PASS;
            
            // If it's a fragment (offset != 0 or M flag), we can't find ports
            struct ipv6_frag_hdr {
                 __u8    nexthdr;
                 __u8    reserved;
                 __be16  frag_off;
                 __be32  identification;
            } *frag = cur_header;
            
            // Check fragment offset and More Fragments flag
            // frag_off is network byte order. Mask 0xFFF8 is offset, 0x0001 is M flag
            if ((frag->frag_off & bpf_htons(0xFFF9)) != 0) {
                 if (cached_drop_frags == 1) return XDP_DROP;
                 return XDP_PASS; // Cannot find L4 header
            }
            
            next_proto = frag->nexthdr;
            cur_header += 8;
        } else {
            // Unknown header or upper layer protocol reached
            break;
        }
    }

    if (next_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = cur_header;
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
    } else if (next_proto == IPPROTO_UDP) {
        struct udphdr *udp = cur_header;
        if ((void *)udp + sizeof(*udp) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dest_port = bpf_ntohs(udp->dest);
        }
    }

    // 0. Anti-Spoofing & Bogon Filter
    if (cached_bogon_filter == 1) {
        if (is_bogon_ipv6(&ip6->saddr)) return XDP_DROP;
    } else {
        if (ip6->saddr.s6_addr[0] == 0xff) return XDP_DROP;
    }

    // 1. Whitelist
    if (is_whitelisted6(&ip6->saddr, dest_port)) return XDP_PASS;

    // 2. Lock list
    struct rule_value *cnt = get_blacklist_stats6(&ip6->saddr);
    if (cnt) {
        __sync_fetch_and_add(&cnt->counter, 1);
        return XDP_DROP;
    }

    // 2.5 Rate limit & SYN Flood protection
    if (cached_ratelimit_enabled == 1) {
        int is_syn = (next_proto == IPPROTO_TCP && (tcp_flags & 0x02));
        if (cached_syn_limit == 0 || is_syn) {
            if (!check_ratelimit6(&ip6->saddr)) {
                return XDP_DROP;
            }
        }
    }

    // 3. Conntrack
    if (cached_ct_enabled == 1) {
        struct ct_key6 look_key = {
            .src_ip = ip6->daddr, .dst_ip = ip6->saddr,
            .src_port = dest_port, .dst_port = src_port,
            .protocol = next_proto,
        };
        struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map6, &look_key);
        if (ct_val && (bpf_ktime_get_ns() - ct_val->last_seen < cached_ct_timeout)) {
            return XDP_PASS;
        }
    }

    // 4. IP+Port rules
    if (dest_port > 0) {
        int rule_action = check_ip6_port_rule(&ip6->saddr, dest_port);
        if (rule_action == 1) return XDP_PASS;
        if (rule_action == 2) return XDP_DROP;
    }

    // 5. ICMPv6
    if (ip6->nexthdr == IPPROTO_ICMPV6 && cached_allow_icmp == 1) {
        if (check_icmp_limit(cached_icmp_rate, cached_icmp_burst)) {
            return XDP_PASS;
        }
        return XDP_DROP;
    }

    // 6. Return traffic
    if (cached_allow_return == 1 && cached_ct_enabled == 0) {
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
            if ((void *)tcp + sizeof(*tcp) <= data_end && tcp->ack && dest_port >= 32768) {
                return XDP_PASS;
            }
        } else if (ip6->nexthdr == IPPROTO_UDP && dest_port >= 32768) {
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

#endif // __NETXFW_IPV6_BPF_C
