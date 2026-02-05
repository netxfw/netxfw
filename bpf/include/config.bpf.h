// SPDX-License-Identifier: MIT
#ifndef __NETXFW_CONFIG_H
#define __NETXFW_CONFIG_H

#include "helpers.bpf.h"

static __always_inline void refresh_config() {
    __u32 key = CONFIG_CONFIG_VERSION;
    __u64 *ver = bpf_map_lookup_elem(&global_config, &key);
    if (ver && *ver != cached_version) {
        cached_version = *ver;

        __u64 *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ENABLE_CONNTRACK});
        if (val) cached_ct_enabled = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ALLOW_ICMP});
        if (val) cached_allow_icmp = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ALLOW_RETURN_TRAFFIC});
        if (val) cached_allow_return = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_DEFAULT_DENY});
        if (val) cached_default_deny = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_CONNTRACK_TIMEOUT});
        if (val) cached_ct_timeout = *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ICMP_RATE});
        if (val) cached_icmp_rate = *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ICMP_BURST});
        if (val) cached_icmp_burst = *val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ENABLE_AF_XDP});
        if (val) cached_af_xdp_enabled = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_STRICT_PROTO});
        if (val) cached_strict_proto = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_ENABLE_RATELIMIT});
        if (val) cached_ratelimit_enabled = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_DROP_FRAGMENTS});
        if (val) cached_drop_frags = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_STRICT_TCP});
        if (val) cached_strict_tcp = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_SYN_LIMIT});
        if (val) cached_syn_limit = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_BOGON_FILTER});
        if (val) cached_bogon_filter = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_AUTO_BLOCK});
        if (val) cached_auto_block = (__u32)*val;

        val = bpf_map_lookup_elem(&global_config, &(__u32){CONFIG_AUTO_BLOCK_EXPIRY});
        if (val) cached_auto_block_expiry = *val;
    }
}

#endif // __NETXFW_CONFIG_H
