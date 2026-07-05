//go:build linux
// +build linux

package xdp

import (
	"sync"

	"github.com/cilium/ebpf"
)

var numCPUCache int

func init() {
	numCPUCache, _ = ebpf.PossibleCPU()
	if numCPUCache <= 0 {
		numCPUCache = 1
	}
}

var statsGlobalSlicePool = sync.Pool{
	New: func() any {
		slice := make([]NetXfwStatsGlobal, numCPUCache)
		return &slice
	},
}

func acquireStatsGlobalSlice() *[]NetXfwStatsGlobal {
	return statsGlobalSlicePool.Get().(*[]NetXfwStatsGlobal)
}

func releaseStatsGlobalSlice(v *[]NetXfwStatsGlobal) {
	for i := range *v {
		(*v)[i] = NetXfwStatsGlobal{}
	}
	statsGlobalSlicePool.Put(v)
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
