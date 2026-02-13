// SPDX-License-Identifier: MIT
#ifndef __NETXFW_RATELIMIT_BPF_C
#define __NETXFW_RATELIMIT_BPF_C

#include "../include/protocol.h"
#include "../include/maps.bpf.h"
#include "../include/helpers.bpf.h"

// Forward declaration if not included
// Note: blacklist.bpf.c should be included before this file in netxfw.bpf.c

/**
 * Helper to check general rate limit for an IP address (IPv4-mapped or IPv6)
 */
static __always_inline int check_ratelimit(struct in6_addr *ip) {
    struct ratelimit_stats *stats = bpf_map_lookup_elem(&ratelimit_state, ip);
    
    // 1. If we have a cached state, check if the config version is still valid
    if (likely(stats && stats->config_version == cached_version)) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - stats->last_time;
        
        // Fast path: < 1ms, skip math
        if (likely(elapsed < 1000000ULL)) {
            if (likely(stats->tokens >= 1)) {
                stats->tokens -= 1;
                return 1;
            }
            // Rate limit exceeded: Auto-block if enabled
            add_to_blacklist(ip);
            return 0;
        }

        __u64 tokens_to_add = (elapsed * stats->rate) / 1000000000ULL;
        __u64 new_tokens = stats->tokens + tokens_to_add;
        if (new_tokens > stats->burst) new_tokens = stats->burst;

        if (likely(new_tokens >= 1)) {
            stats->tokens = new_tokens - 1;
            stats->last_time = now;
            return 1;
        }

        // Rate limit exceeded: Auto-block if enabled
        add_to_blacklist(ip);
        return 0;
    }

    // 2. No state or stale config: lookup CIDR configuration (LPM)
    // Use /128 for exact match if needed, but here we want to match config.
    // For IPv4 mapped, we should probably check if there is a config for ::ffff:ip/128 or ::ffff:net/prefix?
    // The Go side should populate ratelimit_config with mapped addresses.
    // So we just lookup the mapped address in the LPM.
    struct lpm_key key = { .prefixlen = 128 };
    __builtin_memcpy(&key.data, ip, sizeof(struct in6_addr));

    struct ratelimit_conf *conf = bpf_map_lookup_elem(&ratelimit_config, &key);
    if (unlikely(!conf)) return 1;

    // 3. Update or create state with new config
    if (stats) {
        stats->rate = conf->rate;
        stats->burst = conf->burst;
        stats->config_version = cached_version;
        // Keep current tokens/last_time or reset? Resetting is safer for config changes.
        stats->tokens = conf->burst;
        stats->last_time = bpf_ktime_get_ns();
    } else {
        struct ratelimit_stats new_stats = {
            .last_time = bpf_ktime_get_ns(),
            .tokens = conf->burst,
            .rate = conf->rate,
            .burst = conf->burst,
            .config_version = cached_version,
        };
        bpf_map_update_elem(&ratelimit_state, ip, &new_stats, BPF_ANY);
    }
    return 1;
}

#endif // __NETXFW_RATELIMIT_BPF_C
