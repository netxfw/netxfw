// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __NETXFW_PROTOCOL_H
#define __NETXFW_PROTOCOL_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// IPv6 Extension Headers
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct ipv6_frag_hdr {
    __u8    nexthdr;
    __u8    reserved;
    __be16  frag_off;
    __be32  identification;
};

/**
 * Plugin return codes
 * 插件返回值
 */

// Jump table indices for dynamic modules
// 动态模块的跳转表索引
#define PROG_IDX_IPV4 0
#define PROG_IDX_IPV6 1

// Plugin indices (2-15)
// 插件索引 (2-15)
#define PROG_IDX_PLUGIN_START 2
#define PROG_IDX_PLUGIN_END   15

// Drop Reasons
// 丢弃原因
#define DROP_REASON_UNKNOWN     0
#define DROP_REASON_INVALID     1
#define DROP_REASON_PROTOCOL    2
#define DROP_REASON_BLACKLIST   3
#define DROP_REASON_RATELIMIT   4
#define DROP_REASON_STRICT_TCP  5
#define DROP_REASON_DEFAULT     6
#define DROP_REASON_LAND_ATTACK 7
#define DROP_REASON_BOGON       8
#define DROP_REASON_FRAGMENT    9
#define DROP_REASON_BAD_HEADER  10
#define DROP_REASON_TCP_FLAGS   11
#define DROP_REASON_SPOOF       12

// Pass Reasons (start from 100 to avoid conflict if mixed)
// 通过原因（从 100 开始，以避免混合时冲突）
#define PASS_REASON_UNKNOWN     100
#define PASS_REASON_WHITELIST   101
#define PASS_REASON_RETURN      102
#define PASS_REASON_CONNTRACK   103
#define PASS_REASON_DEFAULT     104

#endif // __NETXFW_PROTOCOL_H
