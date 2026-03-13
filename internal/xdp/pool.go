//go:build linux
// +build linux

package xdp

import (
	"sync"

	"github.com/cilium/ebpf"
)

var (
	ruleValuePool = sync.Pool{
		New: func() any {
			return new(NetXfwRuleValue)
		},
	}

	in6AddrPool = sync.Pool{
		New: func() any {
			return new(NetXfwIn6Addr)
		},
	}

	ratelimitValuePool = sync.Pool{
		New: func() any {
			return new(NetXfwRatelimitValue)
		},
	}

	lpmKeyPool = sync.Pool{
		New: func() any {
			return new(NetXfwLpmKey)
		},
	}

	lpmIPPortKeyPool = sync.Pool{
		New: func() any {
			return new(NetXfwLpmIpPortKey)
		},
	}
)

var numCPUCache int

func init() {
	numCPUCache, _ = ebpf.PossibleCPU()
	if numCPUCache <= 0 {
		numCPUCache = 1
	}
}

// acquireRuleValue gets a NetXfwRuleValue from the pool.
// acquireRuleValue 从对象池获取一个 NetXfwRuleValue。
func acquireRuleValue() *NetXfwRuleValue {
	return ruleValuePool.Get().(*NetXfwRuleValue)
}

// releaseRuleValue returns a NetXfwRuleValue to the pool after resetting it.
// releaseRuleValue 将 NetXfwRuleValue 重置后归还到对象池。
func releaseRuleValue(v *NetXfwRuleValue) {
	*v = NetXfwRuleValue{}
	ruleValuePool.Put(v)
}

// acquireIn6Addr gets a NetXfwIn6Addr from the pool.
// acquireIn6Addr 从对象池获取一个 NetXfwIn6Addr。
func acquireIn6Addr() *NetXfwIn6Addr {
	return in6AddrPool.Get().(*NetXfwIn6Addr)
}

// releaseIn6Addr returns a NetXfwIn6Addr to the pool after resetting it.
// releaseIn6Addr 将 NetXfwIn6Addr 重置后归还到对象池。
func releaseIn6Addr(v *NetXfwIn6Addr) {
	*v = NetXfwIn6Addr{}
	in6AddrPool.Put(v)
}

// acquireRatelimitValue gets a NetXfwRatelimitValue from the pool.
// acquireRatelimitValue 从对象池获取一个 NetXfwRatelimitValue。
func acquireRatelimitValue() *NetXfwRatelimitValue {
	return ratelimitValuePool.Get().(*NetXfwRatelimitValue)
}

// releaseRatelimitValue returns a NetXfwRatelimitValue to the pool after resetting it.
// releaseRatelimitValue 将 NetXfwRatelimitValue 重置后归还到对象池。
func releaseRatelimitValue(v *NetXfwRatelimitValue) {
	*v = NetXfwRatelimitValue{}
	ratelimitValuePool.Put(v)
}

// acquireLpmKey gets a NetXfwLpmKey from the pool.
// acquireLpmKey 从对象池获取一个 NetXfwLpmKey。
func acquireLpmKey() *NetXfwLpmKey {
	return lpmKeyPool.Get().(*NetXfwLpmKey)
}

// releaseLpmKey returns a NetXfwLpmKey to the pool after resetting it.
// releaseLpmKey 将 NetXfwLpmKey 重置后归还到对象池。
func releaseLpmKey(v *NetXfwLpmKey) {
	*v = NetXfwLpmKey{}
	lpmKeyPool.Put(v)
}

// acquireLpmIPPortKey gets a NetXfwLpmIpPortKey from the pool.
// acquireLpmIPPortKey 从对象池获取一个 NetXfwLpmIpPortKey。
func acquireLpmIPPortKey() *NetXfwLpmIpPortKey {
	return lpmIPPortKeyPool.Get().(*NetXfwLpmIpPortKey)
}

// releaseLpmIPPortKey returns a NetXfwLpmIpPortKey to the pool after resetting it.
// releaseLpmIPPortKey 将 NetXfwLpmIpPortKey 重置后归还到对象池。
func releaseLpmIPPortKey(v *NetXfwLpmIpPortKey) {
	*v = NetXfwLpmIpPortKey{}
	lpmIPPortKeyPool.Put(v)
}

var ruleValueSlicePool = sync.Pool{
	New: func() any {
		slice := make([]NetXfwRuleValue, numCPUCache)
		return &slice
	},
}

// acquireRuleValueSlice gets a slice of NetXfwRuleValue from the pool.
// The slice length equals the number of possible CPUs for PERCPU map operations.
// acquireRuleValueSlice 从对象池获取一个 NetXfwRuleValue 切片。
// 切片长度等于可能的 CPU 数量，用于 PERCPU Map 操作。
func acquireRuleValueSlice() *[]NetXfwRuleValue {
	return ruleValueSlicePool.Get().(*[]NetXfwRuleValue)
}

// releaseRuleValueSlice returns a slice of NetXfwRuleValue to the pool after resetting all elements.
// releaseRuleValueSlice 将 NetXfwRuleValue 切片所有元素重置后归还到对象池。
func releaseRuleValueSlice(v *[]NetXfwRuleValue) {
	for i := range *v {
		(*v)[i] = NetXfwRuleValue{}
	}
	ruleValueSlicePool.Put(v)
}
