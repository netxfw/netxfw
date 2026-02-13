// SPDX-License-Identifier: MIT
#ifndef __NETXFW_IPV6_BPF_C
#define __NETXFW_IPV6_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"
#include "../include/config.bpf.h"

// Include necessary modules
// 包含必要的模块
#include "../modules/blacklist.bpf.c"
#include "../modules/filter.bpf.c"
#include "../modules/ratelimit.bpf.c"
#include "../modules/rules.bpf.c"
#include "../modules/icmp.bpf.c"

static __always_inline int handle_ipv6(struct xdp_md *ctx, void *data_end, void *ip_header) {
    struct ipv6hdr *ip6 = ip_header;
    if (unlikely((void *)ip6 + sizeof(*ip6) > data_end))
        return XDP_PASS;

    __u16 src_port = 0, dest_port = 0;
    __u8 tcp_flags = 0;
    __u8 next_proto = ip6->nexthdr;
    void *cur_header = (void *)ip6 + sizeof(*ip6);

    // Skip IPv6 extension headers
    // 跳过 IPv6 扩展头
    #pragma unroll
    for (int i = 0; i < 4; i++) { // Limit loop to prevent DoS/verifier issues
        if (unlikely(cur_header + 2 > data_end)) break; // Need at least 2 bytes for next header

        if (likely(next_proto == IPPROTO_TCP || next_proto == IPPROTO_UDP)) break;
        
        // Check for known extension headers
        // 检查已知的扩展头
        if (next_proto == IPPROTO_HOPOPTS || next_proto == IPPROTO_ROUTING || 
            next_proto == IPPROTO_DSTOPTS || next_proto == IPPROTO_AH) {
            
            // Ext header format: [Next Header (1B)][Hdr Ext Len (1B)][...payload...]
            // Length is in 8-octet units, not including the first 8 octets
            // 扩展头格式：[下一个头 (1B)][头扩展长度 (1B)][...负载...]
            // 长度以 8 字节为单位，不包括前 8 个字节
            __u8 *hdr_ptr = cur_header;
            next_proto = *hdr_ptr;
            __u8 len_val = *(hdr_ptr + 1);
            
            // RFC 2460: Length field is in 8-octet units, excluding the first 8 octets
            // Actual length = (len_val + 1) * 8
            // RFC 2460：长度字段以 8 字节为单位，不包括前 8 个字节
            // 实际长度 = (len_val + 1) * 8
            int ext_len = (len_val + 1) * 8;
            
            if (unlikely(cur_header + ext_len > data_end)) return XDP_PASS; // Malformed
            cur_header += ext_len;
        } else if (next_proto == IPPROTO_FRAGMENT) {
            // Fragment header is fixed 8 bytes
            // 分片头固定为 8 字节
            if (unlikely(cur_header + 8 > data_end)) return XDP_PASS;
            
            // If it's a fragment (offset != 0 or M flag), we can't find ports
            // 如果是分片（偏移量 != 0 或 M 标志），我们无法找到端口
            struct ipv6_frag_hdr *frag = cur_header;
            
            // Check fragment offset and More Fragments flag
            // frag_off is network byte order. Mask 0xFFF8 is offset, 0x0001 is M flag
            // 检查分片偏移量和更多分片标志
            // frag_off 是网络字节序。掩码 0xFFF8 是偏移量，0x0001 是 M 标志
            if (unlikely((frag->frag_off & bpf_htons(0xFFF9)) != 0)) {
                 if (cached_drop_frags == 1) {
                     update_drop_stats_with_reason(DROP_REASON_FRAGMENT, next_proto, &ip6->saddr, dest_port);
                     return XDP_DROP;
                 }
                 return XDP_PASS; // Cannot find L4 header
            }
            
            next_proto = frag->nexthdr;
            cur_header += 8;
        } else {
            // Unknown header or upper layer protocol reached
            // 未知头或到达上层协议
            break;
        }
    }

    if (likely(next_proto == IPPROTO_TCP)) {
        struct tcphdr *tcp = cur_header;
        if (likely((void *)tcp + sizeof(*tcp) <= data_end)) {
            src_port = bpf_ntohs(tcp->source);
            dest_port = bpf_ntohs(tcp->dest);
            if (likely(tcp->doff >= 5)) {
                tcp_flags = ((__u8 *)tcp)[13];
                // Strict TCP validation
                // 严格的 TCP 验证
                if (unlikely(cached_strict_tcp == 1)) {
                    if (unlikely(is_invalid_tcp_flags(tcp_flags))) {
                        update_drop_stats_with_reason(DROP_REASON_STRICT_TCP, next_proto, &ip6->saddr, dest_port);
                        return XDP_DROP;
                    }
                } else {
                    // Basic sanity even if strict mode is off
                    // 即使关闭严格模式，也进行基本合法性检查
                    if (unlikely(tcp_flags == 0 || (tcp->syn && tcp->fin))) {
                        update_drop_stats_with_reason(DROP_REASON_TCP_FLAGS, next_proto, &ip6->saddr, dest_port);
                        return XDP_DROP;
                    }
                }
            }
        }
    } else if (next_proto == IPPROTO_UDP) {
        struct udphdr *udp = cur_header;
        if (likely((void *)udp + sizeof(*udp) <= data_end)) {
            src_port = bpf_ntohs(udp->source);
            dest_port = bpf_ntohs(udp->dest);
        }
    }
    
    // Land Attack (IPv6)
    // Land 攻击 (IPv6)
    if (unlikely(is_land_attack_ipv6(&ip6->saddr, &ip6->daddr))) {
        update_drop_stats_with_reason(DROP_REASON_LAND_ATTACK, next_proto, &ip6->saddr, dest_port);
        return XDP_DROP;
    }

    // 0. Anti-Spoofing & Bogon Filter
    // 0. 防欺骗和 Bogon 过滤
    if (unlikely(cached_bogon_filter == 1)) {
        if (unlikely(is_bogon_ipv6(&ip6->saddr))) {
            update_drop_stats_with_reason(DROP_REASON_INVALID, next_proto, &ip6->saddr, dest_port);
            return XDP_DROP;
        }
    } else {
        // Basic multicast source check
        // 基本多播源检查
        if (unlikely(ip6->saddr.s6_addr[0] == 0xff)) {
             update_drop_stats_with_reason(DROP_REASON_INVALID, next_proto, &ip6->saddr, dest_port);
             return XDP_DROP;
        }
    }

    // 1. Whitelist (Unified)
    // 1. 白名单（统一）
    if (unlikely(is_whitelisted(&ip6->saddr, dest_port))) {
        update_pass_stats_with_reason(PASS_REASON_WHITELIST, next_proto, &ip6->saddr, dest_port);
        return XDP_PASS;
    }

    // 2. Lock list (Unified)
    // 2. 锁定列表（统一）
    struct rule_value *cnt = get_blacklist_stats(&ip6->saddr);
    if (unlikely(cnt)) {
        __sync_fetch_and_add(&cnt->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, next_proto, &ip6->saddr, dest_port);
        return XDP_DROP;
    }

    // 2.5 Rate limit & SYN Flood protection (Unified)
    // 2.5 速率限制和 SYN Flood 保护（统一）
    if (likely(cached_ratelimit_enabled == 1)) {
        int is_syn = (next_proto == IPPROTO_TCP && (tcp_flags & 0x02));
        
        if (likely(cached_syn_limit == 0 || is_syn)) {
            if (unlikely(!check_ratelimit(&ip6->saddr))) {
                update_drop_stats_with_reason(DROP_REASON_RATELIMIT, next_proto, &ip6->saddr, dest_port);
                return XDP_DROP;
            }
        }
    }

    // 3. Conntrack (Unified)
    // 3. 连接跟踪（统一）
    if (likely(cached_ct_enabled == 1)) {
        struct ct_key look_key = {
            .src_ip = ip6->daddr, 
            .dst_ip = ip6->saddr,
            .src_port = dest_port, 
            .dst_port = src_port,
            .protocol = next_proto,
        };
        struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &look_key);
        if (likely(ct_val && (bpf_ktime_get_ns() - ct_val->last_seen < cached_ct_timeout))) {
            update_pass_stats_with_reason(PASS_REASON_CONNTRACK, next_proto, &ip6->saddr, dest_port);
            return XDP_PASS;
        }
    }

    // 4. IP+Port rules (Unified)
    // 4. IP+端口规则（统一）
    if (dest_port > 0) {
        int rule_action = check_ip_port_rule(&ip6->saddr, dest_port);
        if (unlikely(rule_action == 1)) {
             update_pass_stats_with_reason(PASS_REASON_WHITELIST, next_proto, &ip6->saddr, dest_port);
             return XDP_PASS;
        }
        if (unlikely(rule_action == 2)) {
             update_drop_stats_with_reason(DROP_REASON_BLACKLIST, next_proto, &ip6->saddr, dest_port);
             return XDP_DROP;
        }
    }

    // 5. ICMPv6
    // 5. ICMPv6
    if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6 && cached_allow_icmp == 1)) {
        if (likely(check_icmp_limit(cached_icmp_rate, cached_icmp_burst))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, next_proto, &ip6->saddr, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_RATELIMIT, next_proto, &ip6->saddr, dest_port);
        return XDP_DROP;
    }

    // 6. Return traffic
    // 6. 返回流量
    if (unlikely(cached_allow_return == 1 && cached_ct_enabled == 0)) {
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
            if ((void *)tcp + sizeof(*tcp) <= data_end && tcp->ack && dest_port >= 32768) {
                update_pass_stats_with_reason(PASS_REASON_RETURN, next_proto, &ip6->saddr, dest_port);
                return XDP_PASS;
            }
        } else if (ip6->nexthdr == IPPROTO_UDP && dest_port >= 32768) {
            update_pass_stats_with_reason(PASS_REASON_RETURN, next_proto, &ip6->saddr, dest_port);
            return XDP_PASS;
        }
    }

    // 7. Default Deny / Port Whitelist
    // 7. 默认拒绝 / 端口白名单
    if (likely(dest_port > 0 && cached_default_deny == 1)) {
        if (likely(bpf_map_lookup_elem(&allowed_ports, &dest_port))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, next_proto, &ip6->saddr, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_DEFAULT, next_proto, &ip6->saddr, dest_port);
        return XDP_DROP;
    }

    update_pass_stats_with_reason(PASS_REASON_DEFAULT, next_proto, &ip6->saddr, dest_port);
    return XDP_PASS;
}

#endif // __NETXFW_IPV6_BPF_C
