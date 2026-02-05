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

// Jump table indices for dynamic modules
#define PROG_IDX_IPV4 0
#define PROG_IDX_IPV6 1

// Plugin indices (2-15)
#define PROG_IDX_PLUGIN_START 2
#define PROG_IDX_PLUGIN_END   15

#endif // __NETXFW_PROTOCOL_H
