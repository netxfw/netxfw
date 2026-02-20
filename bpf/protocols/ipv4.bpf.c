// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __NETXFW_IPV4_BPF_C
#define __NETXFW_IPV4_BPF_C

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

static __always_inline int handle_ipv4(struct xdp_md *ctx, void *data_end, void *ip_header) {
    struct iphdr *ip = ip_header;
    if (unlikely((void *)ip + sizeof(*ip) > data_end))
        return XDP_PASS;

    __u16 src_port = 0, dest_port = 0;
    __u8 tcp_flags = 0;

    // Convert to IPv6-mapped address for unified processing
    // 转换为 IPv4 映射的 IPv6 地址以进行统一处理
    struct in6_addr src_ip6 = {};
    ipv4_to_ipv6_mapped(ip->saddr, &src_ip6);
    
    // 0. Sanity Checks & Bogon Filtering
    // 0. 合法性检查和 Bogon 过滤
    if (unlikely(cached_bogon_filter == 1)) {
        // Use IPv4 specific check for original address
        // 对原始地址使用 IPv4 特定检查
        if (unlikely(is_bogon_ipv4(ip->saddr))) {
            update_drop_stats_with_reason(DROP_REASON_BOGON, ip->protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    // Fragmentation check
    // 分片检查
    if (unlikely(cached_drop_frags == 1)) {
        if (unlikely(bpf_ntohs(ip->frag_off) & (IP_MF | IP_OFFSET))) {
            update_drop_stats_with_reason(DROP_REASON_FRAGMENT, ip->protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    // Calculate dynamic IP header length (IHL is in 32-bit words)
    // 计算动态 IP 头长度（IHL 以 32 位字为单位）
    __u32 ip_len = ip->ihl * 4;
    // Sanity check for minimum IP header length
    // 最小 IP 头长度的合法性检查
    if (unlikely(ip_len < sizeof(*ip))) {
        update_drop_stats_with_reason(DROP_REASON_BAD_HEADER, ip->protocol, &src_ip6, dest_port);
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
                // 严格的 TCP 验证
                if (unlikely(cached_strict_tcp == 1)) {
                    if (unlikely(is_invalid_tcp_flags(tcp_flags))) {
                        update_drop_stats_with_reason(DROP_REASON_STRICT_TCP, ip->protocol, &src_ip6, dest_port);
                        return XDP_DROP;
                    }
                } else {
                    // Basic sanity even if strict mode is off
                    // 即使关闭严格模式，也进行基本合法性检查
                    if (unlikely(tcp_flags == 0 || (tcp->syn && tcp->fin))) {
                        update_drop_stats_with_reason(DROP_REASON_TCP_FLAGS, ip->protocol, &src_ip6, dest_port);
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
    // 0. 防欺骗和 Land 攻击
    if (unlikely((ip->saddr & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000) || ip->saddr == bpf_htonl(0xffffffff))) {
        update_drop_stats_with_reason(DROP_REASON_SPOOF, ip->protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }
    if (unlikely(is_land_attack_ipv4(ip->saddr, ip->daddr))) {
        update_drop_stats_with_reason(DROP_REASON_LAND_ATTACK, ip->protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    // 1. Critical Blacklist (highest priority, emergency blocks)
    // 1. 危机黑名单（最高优先级，紧急封锁）
    struct rule_value *critical = bpf_map_lookup_elem(&critical_blacklist, &src_ip6);
    if (unlikely(critical)) {
        __sync_fetch_and_add(&critical->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, ip->protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    // 2. Whitelist
    // 2. 白名单
    if (unlikely(is_whitelisted(&src_ip6, dest_port))) {
        update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, &src_ip6, dest_port);
        return XDP_PASS;
    }

    // 3. Blacklist (static + dynamic)
    // 3. 黑名单（静态 + 动态）
    struct rule_value *cnt = get_blacklist_stats(&src_ip6);
    if (unlikely(cnt)) {
        __sync_fetch_and_add(&cnt->counter, 1);
        update_drop_stats_with_reason(DROP_REASON_BLACKLIST, ip->protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    // 4. Rate limit & SYN Flood protection
    // 4. 速率限制和 SYN Flood 保护
    if (likely(cached_ratelimit_enabled == 1)) {
        // If it's a SYN packet and SYN limit is enabled, always check rate limit
        // 如果是 SYN 包且启用了 SYN 限制，则始终检查速率限制
        // Or if it's just general rate limiting
        // 或者如果只是通用速率限制
        int is_syn = (ip->protocol == IPPROTO_TCP && (tcp_flags & 0x02));
        
        if (likely(cached_syn_limit == 0 || is_syn)) {
            if (unlikely(!check_ratelimit(&src_ip6))) {
                update_drop_stats_with_reason(DROP_REASON_RATELIMIT, ip->protocol, &src_ip6, dest_port);
                return XDP_DROP;
            }
        }
    }

    // 5. Conntrack
    // 5. 连接跟踪
    if (likely(cached_ct_enabled == 1)) {
        struct in6_addr dst_ip6 = {};
        ipv4_to_ipv6_mapped(ip->daddr, &dst_ip6);
        
        struct ct_key look_key = {
            // Using mapped addresses for unified lookup
            // 使用映射地址进行统一查找
            // Original: src=daddr, dst=saddr (reverse flow check)
            // 原始：src=daddr, dst=saddr（反向流检查）
            .src_ip = dst_ip6, 
            .dst_ip = src_ip6,
            .src_port = dest_port, 
            .dst_port = src_port,
            .protocol = ip->protocol,
        };
        struct ct_value *ct_val = bpf_map_lookup_elem(&conntrack_map, &look_key);
        if (likely(ct_val && (bpf_ktime_get_ns() - ct_val->last_seen < cached_ct_timeout))) {
            update_pass_stats_with_reason(PASS_REASON_CONNTRACK, ip->protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
    }

    // 6. IP+Port rules
    // 6. IP+端口规则
    if (dest_port > 0) {
        int rule_action = check_ip_port_rule(&src_ip6, dest_port);
        if (unlikely(rule_action == 1)) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
        if (unlikely(rule_action == 2)) {
            update_drop_stats_with_reason(DROP_REASON_BLACKLIST, ip->protocol, &src_ip6, dest_port);
            return XDP_DROP;
        }
    }

    // 7. ICMP
    // 7. ICMP
    if (unlikely(ip->protocol == IPPROTO_ICMP && cached_allow_icmp == 1)) {
        if (likely(check_icmp_limit(cached_icmp_rate, cached_icmp_burst))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_RATELIMIT, ip->protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    // 8. Return traffic
    // 8. 返回流量
    if (unlikely(cached_allow_return == 1 && cached_ct_enabled == 0)) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end && tcp->ack && dest_port >= 32768) {
                update_pass_stats_with_reason(PASS_REASON_RETURN, ip->protocol, &src_ip6, dest_port);
                return XDP_PASS;
            }
        } else if (ip->protocol == IPPROTO_UDP && dest_port >= 32768) {
            update_pass_stats_with_reason(PASS_REASON_RETURN, ip->protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
    }

    // 9. Default Deny / Port Whitelist
    // 9. 默认拒绝 / 端口白名单
    if (likely(dest_port > 0 && cached_default_deny == 1)) {
        if (likely(bpf_map_lookup_elem(&allowed_ports, &dest_port))) {
            update_pass_stats_with_reason(PASS_REASON_WHITELIST, ip->protocol, &src_ip6, dest_port);
            return XDP_PASS;
        }
        update_drop_stats_with_reason(DROP_REASON_DEFAULT, ip->protocol, &src_ip6, dest_port);
        return XDP_DROP;
    }

    update_pass_stats_with_reason(PASS_REASON_DEFAULT, ip->protocol, &src_ip6, dest_port);
    return XDP_PASS;
}

#endif // __NETXFW_IPV4_BPF_C
