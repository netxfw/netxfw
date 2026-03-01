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

func acquireRuleValue() *NetXfwRuleValue {
	return ruleValuePool.Get().(*NetXfwRuleValue)
}

func releaseRuleValue(v *NetXfwRuleValue) {
	*v = NetXfwRuleValue{}
	ruleValuePool.Put(v)
}

func acquireIn6Addr() *NetXfwIn6Addr {
	return in6AddrPool.Get().(*NetXfwIn6Addr)
}

func releaseIn6Addr(v *NetXfwIn6Addr) {
	*v = NetXfwIn6Addr{}
	in6AddrPool.Put(v)
}

func acquireRatelimitValue() *NetXfwRatelimitValue {
	return ratelimitValuePool.Get().(*NetXfwRatelimitValue)
}

func releaseRatelimitValue(v *NetXfwRatelimitValue) {
	*v = NetXfwRatelimitValue{}
	ratelimitValuePool.Put(v)
}

func acquireLpmKey() *NetXfwLpmKey {
	return lpmKeyPool.Get().(*NetXfwLpmKey)
}

func releaseLpmKey(v *NetXfwLpmKey) {
	*v = NetXfwLpmKey{}
	lpmKeyPool.Put(v)
}

func acquireLpmIPPortKey() *NetXfwLpmIpPortKey {
	return lpmIPPortKeyPool.Get().(*NetXfwLpmIpPortKey)
}

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

func acquireRuleValueSlice() *[]NetXfwRuleValue {
	return ruleValueSlicePool.Get().(*[]NetXfwRuleValue)
}

func releaseRuleValueSlice(v *[]NetXfwRuleValue) {
	for i := range *v {
		(*v)[i] = NetXfwRuleValue{}
	}
	ruleValueSlicePool.Put(v)
}
