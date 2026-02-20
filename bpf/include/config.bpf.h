// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __NETXFW_CONFIG_H
#define __NETXFW_CONFIG_H

#include "helpers.bpf.h"

static __always_inline void refresh_config() {
    __u32 key = CONFIG_CONFIG_VERSION;
    __u64 *ver = bpf_map_lookup_elem(&global_config, &key);
    if (ver && *ver != cached_version) {
        cached_version = *ver;

        __u64 *val;
        __u32 k;

        // Update all cached configurations
        // 更新所有缓存的配置
        k = CONFIG_ENABLE_CONNTRACK;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_ct_enabled = (__u32)*val;

        k = CONFIG_ALLOW_ICMP;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_allow_icmp = (__u32)*val;

        k = CONFIG_ALLOW_RETURN_TRAFFIC;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_allow_return = (__u32)*val;

        k = CONFIG_DEFAULT_DENY;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_default_deny = (__u32)*val;

        k = CONFIG_CONNTRACK_TIMEOUT;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_ct_timeout = *val;

        k = CONFIG_ICMP_RATE;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_icmp_rate = *val;

        k = CONFIG_ICMP_BURST;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_icmp_burst = *val;

        k = CONFIG_ENABLE_AF_XDP;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_af_xdp_enabled = (__u32)*val;

        k = CONFIG_STRICT_PROTO;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_strict_proto = (__u32)*val;

        k = CONFIG_ENABLE_RATELIMIT;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_ratelimit_enabled = (__u32)*val;

        k = CONFIG_DROP_FRAGMENTS;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_drop_frags = (__u32)*val;

        k = CONFIG_STRICT_TCP;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_strict_tcp = (__u32)*val;

        k = CONFIG_SYN_LIMIT;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_syn_limit = (__u32)*val;

        k = CONFIG_BOGON_FILTER;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_bogon_filter = (__u32)*val;

        k = CONFIG_AUTO_BLOCK;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_auto_block = (__u32)*val;

        k = CONFIG_AUTO_BLOCK_EXPIRY;
        val = bpf_map_lookup_elem(&global_config, &k);
        if (val) cached_auto_block_expiry = *val;
    }
}

#endif // __NETXFW_CONFIG_H
