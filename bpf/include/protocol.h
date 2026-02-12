// SPDX-License-Identifier: MIT
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

// Jump table indices for dynamic modules
#define PROG_IDX_IPV4 0
#define PROG_IDX_IPV6 1

// Plugin indices (2-15)
#define PROG_IDX_PLUGIN_START 2
#define PROG_IDX_PLUGIN_END   15

#endif // __NETXFW_PROTOCOL_H
