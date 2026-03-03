# netxfw BPF Filter Flow Summary

## Packet Processing Order

1. **Protocol Recognition** → 2. **Basic Check** → 3. **Whitelist** → 4. **Dynamic Blacklist** → 5. **Static Blacklist** → 6. **Rate Limiting** → 7. **Connection Tracking** → 8. **IP+Port Rules** → 9. **ICMP Filtering** → 10. **Return Traffic** → 11. **Default Policy**

## Key Features

- **Dynamic Blacklist**: LRU hash table, supports automatic blocking and expiration
- **Static Blacklist**: LPM Trie, supports CIDR subnet matching
- **Sampled Configuration Update**: Update configuration every 1000 packets
- **Connection Tracking**: Supports automatic pass of return traffic
- **LPM Trie**: Efficient IP range matching
- **Modular Design**: Independent functions, easy to extend

## Configuration-driven

All behaviors are controlled by parameters in the `global_config` mapping table, supporting hot update.