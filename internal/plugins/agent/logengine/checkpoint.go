package logengine

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/nxadm/tail"
)

const CheckpointFile = "/var/lib/netxfw/log_offsets.json"

// CheckpointManager handles persistence of file offsets.
type CheckpointManager struct {
	logger  sdk.Logger
	mu      sync.Mutex
	offsets map[string]int64
	file    string
	ticker  *time.Ticker
	stop    chan struct{}
}

// NewCheckpointManager creates a new manager.
func NewCheckpointManager(logger sdk.Logger) *CheckpointManager {
	return &CheckpointManager{
		logger:  logger,
		offsets: make(map[string]int64),
		file:    CheckpointFile,
		stop:    make(chan struct{}),
	}
}

// Load reads offsets from disk.
func (cm *CheckpointManager) Load() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.file)
	if err != nil {
		if !os.IsNotExist(err) {
			cm.logger.Warnf("⚠️  Failed to load checkpoints: %v", err)
		}
		return
	}

	if err := json.Unmarshal(data, &cm.offsets); err != nil {
		cm.logger.Warnf("⚠️  Failed to parse checkpoints: %v", err)
	}
}

// Save writes offsets to disk.
func (cm *CheckpointManager) Save() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := json.MarshalIndent(cm.offsets, "", "  ")
	if err != nil {
		cm.logger.Warnf("⚠️  Failed to marshal checkpoints: %v", err)
		return
	}

	// Ensure directory exists
	_ = os.MkdirAll("/var/lib/netxfw", 0755)

	if err := os.WriteFile(cm.file, data, 0644); err != nil {
		cm.logger.Warnf("⚠️  Failed to save checkpoints: %v", err)
	}
}

// Start periodic saving.
func (cm *CheckpointManager) Start() {
	cm.Load()
	cm.ticker = time.NewTicker(2 * time.Second)
	go func() {
		for {
			select {
			case <-cm.ticker.C:
				cm.Save()
			case <-cm.stop:
				return
			}
		}
	}()
}

// Stop stops periodic saving and does a final save.
func (cm *CheckpointManager) Stop() {
	if cm.ticker != nil {
		cm.ticker.Stop()
	}
	close(cm.stop)
	cm.Save()
}

// UpdateOffset updates the offset for a file.
func (cm *CheckpointManager) UpdateOffset(file string, offset int64) {
	cm.mu.Lock()
	cm.offsets[file] = offset
	cm.mu.Unlock()
}

// GetOffset returns the SeekInfo for a file based on policy.
// mode: "start", "end", "offset"
func (cm *CheckpointManager) GetOffset(file string, mode string) *tail.SeekInfo {
	cm.mu.Lock()
	savedOffset, ok := cm.offsets[file]
	cm.mu.Unlock()

	// Default fallback to End if unknown mode
	whence := 2 // End
	offset := int64(0)

	switch mode {
	case "start":
		whence = 0
		offset = 0
	case "offset":
		if ok {
			// Validate file size to detect rotation
			info, err := os.Stat(file)
			if err == nil {
				if info.Size() < savedOffset {
					log.Printf("🔄 Log rotation detected for %s (size %d < offset %d). Resetting to start.", file, info.Size(), savedOffset)
					return &tail.SeekInfo{Offset: 0, Whence: 0}
				}
				// Resume
				return &tail.SeekInfo{Offset: savedOffset, Whence: 0}
			}
		}
		// If offset not found or file error, what should default be for "offset" mode?
		// Usually "end" to avoid re-reading everything if state is lost.
		whence = 2
		offset = 0
	case "end":
		whence = 2
		offset = 0
	default:
		// Default to End
		whence = 2
		offset = 0
	}

	return &tail.SeekInfo{Offset: offset, Whence: whence}
}
