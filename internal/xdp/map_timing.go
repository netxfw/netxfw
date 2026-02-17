package xdp

import (
	"time"
)

// TimedMapOp wraps a map operation with latency tracking.
// TimedMapOp 包装 Map 操作并跟踪延迟。
type TimedMapOp struct {
	stats   *PerformanceStats
	mapName string
	opType  string
	start   time.Time
}

// BeginMapOp starts timing a map operation.
// BeginMapOp 开始计时 Map 操作。
func (p *PerformanceStats) BeginMapOp(mapName, opType string) *TimedMapOp {
	return &TimedMapOp{
		stats:   p,
		mapName: mapName,
		opType:  opType,
		start:   time.Now(),
	}
}

// End completes the timing and records the operation.
// End 完成计时并记录操作。
func (t *TimedMapOp) End(err error) {
	if t.stats == nil {
		return
	}
	latency := time.Since(t.start).Nanoseconds()
	hasError := err != nil
	t.stats.RecordMapOperation(t.mapName, t.opType, uint64(latency), hasError)
}

// MapOpHelper provides helper functions for timed map operations.
// MapOpHelper 提供定时 Map 操作的辅助函数。
type MapOpHelper struct {
	stats   *PerformanceStats
	mapName string
}

// NewMapOpHelper creates a new map operation helper.
// NewMapOpHelper 创建新的 Map 操作辅助器。
func NewMapOpHelper(stats *PerformanceStats, mapName string) *MapOpHelper {
	return &MapOpHelper{
		stats:   stats,
		mapName: mapName,
	}
}

// TimeRead times a read operation.
// TimeRead 计时读操作。
func (h *MapOpHelper) TimeRead(fn func() error) error {
	op := h.stats.BeginMapOp(h.mapName, "read")
	err := fn()
	op.End(err)
	return err
}

// TimeWrite times a write operation.
// TimeWrite 计时写操作。
func (h *MapOpHelper) TimeWrite(fn func() error) error {
	op := h.stats.BeginMapOp(h.mapName, "write")
	err := fn()
	op.End(err)
	return err
}

// TimeDelete times a delete operation.
// TimeDelete 计时删除操作。
func (h *MapOpHelper) TimeDelete(fn func() error) error {
	op := h.stats.BeginMapOp(h.mapName, "delete")
	err := fn()
	op.End(err)
	return err
}

// TimeIter times an iteration operation.
// TimeIter 计时迭代操作。
func (h *MapOpHelper) TimeIter(fn func() error) error {
	op := h.stats.BeginMapOp(h.mapName, "iter")
	err := fn()
	op.End(err)
	return err
}
