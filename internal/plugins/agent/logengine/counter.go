package logengine

import (
	"net/netip"
	"sync"
	"time"
)

const (
	shardsCount = 64
)

// Counter implements a high-performance sliding window counter.
type Counter struct {
	shards           [shardsCount]*counterShard
	statsPool        sync.Pool
	seed             uint64
	maxWindowSeconds int
}

type counterShard struct {
	sync.RWMutex
	// map ip -> stats
	counts map[netip.Addr]*ipStats
}

type ipStats struct {
	buckets      []uint16 // dynamic size slice
	lastIdx      int      // current second index in global time
	lastUnixTime int64    // unix timestamp of the last update
}

// NewCounter creates a new Counter.
func NewCounter(maxWindow int) *Counter {
	if maxWindow <= 0 {
		maxWindow = 3600
	}
	c := &Counter{
		statsPool: sync.Pool{
			New: func() interface{} {
				return &ipStats{}
			},
		},
		// Simple seed initialization
		seed:             uint64(time.Now().UnixNano()),
		maxWindowSeconds: maxWindow,
	}
	for i := 0; i < shardsCount; i++ {
		c.shards[i] = &counterShard{
			counts: make(map[netip.Addr]*ipStats),
		}
	}
	return c
}

func (c *Counter) getShard(ip netip.Addr) *counterShard {
	// Simple and fast hashing for sharding
	var h uint64
	if ip.Is4() {
		b := ip.As4()
		// FNV-1a like mixing for 4 bytes
		h = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24
	} else {
		b := ip.As16()
		// XOR fold for IPv6
		h = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24
		h ^= uint64(b[4]) | uint64(b[5])<<8 | uint64(b[6])<<16 | uint64(b[7])<<24
		h ^= uint64(b[8]) | uint64(b[9])<<8 | uint64(b[10])<<16 | uint64(b[11])<<24
		h ^= uint64(b[12]) | uint64(b[13])<<8 | uint64(b[14])<<16 | uint64(b[15])<<24
	}
	// Mix with seed
	h ^= c.seed
	return c.shards[h%shardsCount]
}

// Inc increments the counter for the given IP at the current time.
func (c *Counter) Inc(ip netip.Addr) {
	shard := c.getShard(ip)
	now := time.Now().Unix()
	mw := int64(c.maxWindowSeconds)

	shard.Lock()
	stats, ok := shard.counts[ip]
	if !ok {
		stats = c.statsPool.Get().(*ipStats)
		// Initialize or Reset stats
		if cap(stats.buckets) < c.maxWindowSeconds {
			stats.buckets = make([]uint16, c.maxWindowSeconds)
		} else {
			stats.buckets = stats.buckets[:c.maxWindowSeconds]
			for i := range stats.buckets {
				stats.buckets[i] = 0
			}
		}

		stats.lastUnixTime = now
		stats.lastIdx = int(now % mw)
		shard.counts[ip] = stats
	}

	idx := int(now % mw)

	// If time has moved forward, clear old buckets between last update and now
	if now > stats.lastUnixTime {
		diff := now - stats.lastUnixTime
		// Fix: Only clear buckets if diff is positive
		if diff > 0 {
			if diff >= mw {
				// Reset all if gap is larger than window
				for i := range stats.buckets {
					stats.buckets[i] = 0
				}
			} else {
				// Clear buckets in the gap
				// We need to clear from (lastIdx + 1) to (lastIdx + diff)
				for i := int64(1); i <= diff; i++ {
					clearIdx := (stats.lastIdx + int(i)) % c.maxWindowSeconds
					stats.buckets[clearIdx] = 0
				}
			}
			stats.lastUnixTime = now
			stats.lastIdx = idx
		}
	} else if now < stats.lastUnixTime {
		// Clock skew or race condition?
		// Just update the bucket for 'now' (which is in the past relative to lastUnixTime)
		// idx calculation above handles this.
	}

	stats.buckets[idx]++
	shard.Unlock()
}

// Count returns the number of hits for the IP in the last windowSeconds.
func (c *Counter) Count(ip netip.Addr, windowSeconds int) int {
	if windowSeconds > c.maxWindowSeconds {
		windowSeconds = c.maxWindowSeconds
	}

	shard := c.getShard(ip)
	shard.RLock()
	defer shard.RUnlock()

	stats, ok := shard.counts[ip]
	if !ok {
		return 0
	}

	now := time.Now().Unix()
	mw := int64(c.maxWindowSeconds)

	if now-stats.lastUnixTime >= mw {
		return 0
	}

	total := 0
	// Iterate backwards from 'now' for 'window' seconds.
	for i := 0; i < windowSeconds; i++ {
		t := now - int64(i)
		if t > stats.lastUnixTime {
			// Future relative to last update, implies 0
			continue
		}
		if t <= stats.lastUnixTime-mw {
			// Too old
			continue
		}

		idx := int(t % mw)
		total += int(stats.buckets[idx])
	}

	return total
}

// Cleanup removes old entries to prevent memory leak.
func (c *Counter) Cleanup() {
	now := time.Now().Unix()
	mw := int64(c.maxWindowSeconds)
	for i := 0; i < shardsCount; i++ {
		shard := c.shards[i]
		shard.Lock()
		for ip, stats := range shard.counts {
			if now-stats.lastUnixTime > mw {
				delete(shard.counts, ip)
				// Return to pool
				c.statsPool.Put(stats)
			}
		}
		shard.Unlock()
	}
}
