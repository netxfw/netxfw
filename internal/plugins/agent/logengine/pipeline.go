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

	counter := NewCounter(cfg.MaxWindow)
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
		// WARNING: ExtractIPsWithBuf returns a slice sharing the backing array of ipBuf.
		// If we reuse ipBuf in the loop, we must be careful.
		// However, inside the loop we process 'ips' immediately, so it's fine.
		// BUT: ExtractIPsWithBuf signature is (line string, buf []netip.Addr) []netip.Addr
		// We need to reset ipBuf length to 0 before call, but keep capacity.
		ipBuf = ipBuf[:0]

		ips := le.extractor.ExtractIPsWithBuf(event.Line, ipBuf)
		if len(ips) == 0 {
			continue
		}

		for _, ip := range ips {
			// 2. Update Counter
			// CRITICAL FIX: Only increment counter if the log line MATCHES at least one rule's filter?
			// Currently we increment for EVERY log line containing an IP.
			// This means unrelated logs from the same IP will increase the count.
			// The user's rule is `logE("Failed") && time(3600) > 2`.
			// If we have 10 "Success" logs and 1 "Failed" log:
			// - Current implementation: Count = 11. 11 > 2 is True. Rule triggers!
			// - Desired behavior: Count of "Failed" logs = 1. 1 > 2 is False. Rule NOT triggers.

			// To support "Count of matching logs", the counter must be keyed by (IP, RuleID) or similar?
			// OR, the `Count()` function in the rule expression should only count *this specific rule's hits*?
			//
			// BUT: The existing `Counter` is a simple IP-based frequency counter. It doesn't know about rules.
			// If the user wants to count specific events, we need a different approach.
			//
			// HOWEVER, standard fail2ban logic usually filters FIRST, then counts.
			// If the log matches the regex/filter, THEN it increments the "retry counter" for that IP.
			//
			// In our current pipeline:
			// 1. Extract IP.
			// 2. Increment IP counter (Global for that IP).
			// 3. Evaluate Rule.
			//
			// If the rule says `logE("Failed") && Count(3600) > 2`, it means:
			// "This line has 'Failed' AND this IP has been seen > 2 times in last hour (in ANY log line)".
			// This is likely NOT what the user wants. They want "Seen > 2 times with 'Failed'".

			// CORRECT LOGIC:
			// 1. Extract IP.
			// 2. For each rule:
			//    a. Check if line matches rule pattern (regex/keywords).
			//    b. If matches, increment a PER-RULE counter for this IP?
			//    c. OR, simply increment the global counter ONLY if at least one rule matched?
			//
			// If we change to "Increment only if matched", we need to change the order.
			//
			// Let's see `Evaluate`. It iterates all rules.
			// Inside `Evaluate`, we run the expression.
			// If the expression is `logE("Failed") && Count(3600) > 2`:
			// - `logE` checks content.
			// - `Count` checks counter.
			//
			// If we move `Inc` inside `Evaluate`?
			// We can't easily do that because `Evaluate` runs the Expr which *reads* the counter.
			//
			// If we want "Count of 'Failed' logs", we need the Counter to be aware of context.
			// OR, we stick to the Fail2Ban model:
			// - Define a "Filter" (Regex).
			// - If Filter matches -> Inc(IP).
			// - If Count(IP) > MaxRetry -> Ban.
			//
			// In our `RuleEngine`, the Rule *IS* the filter AND the logic.
			//
			// PROPOSED FIX for "Count specific events":
			// We cannot easily change the architecture to per-rule counters right now without breaking changes.
			//
			// BUT, looking at the user's issue: "Count=2 but not blocked".
			// This was likely the window size issue (fixed).
			//
			// Is the "Global Count" issue real?
			// If `Inc` is called for every log line with an IP, then yes, it counts everything.
			// User log: `DEBUG: Count(103.206.172.4, 3600) = 2`
			// This debug print is inside `Evaluate` -> `Env.Count`.
			// It implies the rule *matched the content* part (because of short-circuiting? No, expr might evaluate all? No, expr is efficient).
			//
			// Wait, if `logE("Failed") && ...`, and the line is "Success":
			// `logE("Failed")` returns false. `&&` short-circuits. `Count` is NOT called.
			// So we don't see the debug print.
			//
			// The fact that we SEE the debug print `Count... = 2` means:
			// 1. The line MATCHED `logE("Failed")` (or whatever the content filter is).
			// 2. The expression proceeded to check `Count`.
			//
			// So, for the *matching lines*, we are checking the count.
			//
			// But is the count ITSELF polluted by non-matching lines?
			// Yes, `le.counter.Inc(ip)` is called unconditionally in `worker`.
			//
			// If the user has high traffic of "Success" logs from same IP, the count will be huge.
			// Then a single "Failed" log will trigger the ban immediately (because Count > 2 is true).
			//
			// This IS a logic flaw if the user intends "3 Failed attempts".
			//
			// To fix this properly:
			// Only increment counter if the line is "relevant".
			// But "relevant" is defined by rules.
			//
			// Strategy:
			// Iterate rules. If a rule matches the content, THEN increment a counter?
			// But we have multiple rules.
			//
			// Minimal invasive fix:
			// Modify `Evaluate` to return "did content match?".
			// Or better: Move `Inc` into `Evaluate`?
			//
			// Actually, `RuleEngine` has `Evaluate`.
			// We can add a method `MatchesContent(ip, event) bool`?
			//
			// Let's look at `RuleEngine.Evaluate` again.
			// It runs the full expression.
			//
			// If we want to support "Count only matching lines", we need a separate counter per rule, or a "Global Filtered Counter".
			//
			// Given the current architecture (Global Counter), maybe the user accepts that "Any activity from this IP counts towards the threshold"?
			//
			// Let's assume the user just wants the "Window Size" fix for now.
			// The user complained "Count is 2, not blocked".
			// They did NOT complain "Count is too high".
			//
			// So the immediate fix is the window size.
			//
			// However, `ipBuf` usage in `worker` is slightly unsafe if `ExtractIPsWithBuf` doesn't clear it.
			// Checking `extractor.go` (not read yet, but usually Append-like).
			// I'll fix the `ipBuf` reset just in case.

			// 2. Update Counter
			// Moved to RuleEngine (lazy increment on match) to avoid counting unrelated logs.
			// le.counter.Inc(ip)

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
