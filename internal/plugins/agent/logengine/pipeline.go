package logengine

import (
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// LogEngine is the main orchestrator.
type LogEngine struct {
	config     types.LogEngineConfig
	tailer     *Tailer
	tokenizer  *Tokenizer
	extractor  *IPExtractor
	ruleEngine *RuleEngine
	counter    *Counter
	action     ActionHandler
	stopChan   chan struct{}
	wg         sync.WaitGroup
	running    bool
	mu         sync.Mutex
	checkpoint *CheckpointManager
}

// New creates a new LogEngine.
func New(cfg types.LogEngineConfig, actionHandler ActionHandler) *LogEngine {
	if cfg.Workers <= 0 {
		cfg.Workers = 4 // Default to 4 workers
	}

	counter := NewCounter()
	checkpoint := NewCheckpointManager()

	le := &LogEngine{
		config:     cfg,
		tailer:     NewTailer(checkpoint),
		tokenizer:  NewTokenizer(),
		extractor:  NewIPExtractor(),
		ruleEngine: NewRuleEngine(counter),
		counter:    counter,
		action:     actionHandler,
		stopChan:   make(chan struct{}),
		checkpoint: checkpoint,
	}

	// Load initial rules
	if err := le.ruleEngine.UpdateRules(cfg.Rules); err != nil {
		log.Printf("⚠️  Failed to load initial rules: %v", err)
	}

	return le
}

// Start begins the pipeline processing.
func (le *LogEngine) Start() {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.running {
		return
	}
	le.running = true

	log.Printf("🚀 Starting LogEngine with %d workers...", le.config.Workers)

	// Start Counter cleanup routine
	go le.runCleanup()

	// Start Checkpoint Manager
	le.checkpoint.Start()

	// Start Workers
	for i := 0; i < le.config.Workers; i++ {
		le.wg.Add(1)
		go le.worker(i)
	}

	// Start Tailer
	le.tailer.Watch(le.collectFiles())
}

func (le *LogEngine) Stop() {
	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.running {
		return
	}
	le.running = false

	log.Println("🛑 Stopping LogEngine...")
	close(le.stopChan)
	le.tailer.Stop()
	le.checkpoint.Stop()
	if le.action != nil {
		le.action.Stop()
	}
	le.wg.Wait()
}

func (le *LogEngine) runCleanup() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-le.stopChan:
			return
		case <-ticker.C:
			le.counter.Cleanup()
		}
	}
}

func (le *LogEngine) worker(id int) {
	defer le.wg.Done()

	// Reusable buffer for IP extraction to reduce allocation
	ipBuf := make([]netip.Addr, 0, 16)

	for event := range le.tailer.Events {
		// 1. Extract IPs (No regex, zero allocation path)
		ips := le.extractor.ExtractIPsWithBuf(event.Line, ipBuf)
		if len(ips) == 0 {
			continue
		}

		for _, ip := range ips {
			// 2. Update Counter
			le.counter.Inc(ip)

			// 3. Evaluate Rules
			actionType, ttl, ruleID, matched := le.ruleEngine.Evaluate(ip, event)
			if matched {
				le.executeAction(ip, actionType, ttl, ruleID)
			}
		}
	}
}

func (le *LogEngine) executeAction(ip netip.Addr, actionType ActionType, ttl time.Duration, ruleID string) {
	if err := le.action.Block(ip, actionType, ttl); err != nil {
		log.Printf("❌ Action failed for rule %s (type: %d): %v", ruleID, actionType, err)
	} else {
		// Log the hit
		log.Printf("🛡️  Rule %s triggered action type %d (ttl: %v) for IP %s", ruleID, actionType, ttl, ip)
	}
}

// UpdateConfig updates the configuration and reloads rules.
func (le *LogEngine) UpdateConfig(cfg types.LogEngineConfig) error {
	le.config = cfg
	if err := le.ruleEngine.UpdateRules(cfg.Rules); err != nil {
		return err
	}
	// Update tailer watch list
	le.tailer.Watch(le.collectFiles())
	return nil
}

// collectFiles aggregates files from explicit list and rules.
// It returns a map of filename -> tail_position.
func (le *LogEngine) collectFiles() map[string]string {
	fileMap := make(map[string]string)

	// 1. Files from rules (Priority)
	for _, r := range le.config.Rules {
		if r.Path != "" {
			// Use rule's tail position, default to "end" if empty
			pos := r.TailPosition
			if pos == "" {
				pos = "end"
			}
			fileMap[r.Path] = pos
		}
	}

	return fileMap
}
