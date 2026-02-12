package logengine

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// Rule represents a compiled rule.
type Rule struct {
	ID         string
	Path       string // Path pattern to match against Source
	Source     string
	Program    *vm.Program
	Action     string
	ActionType ActionType
	TTL        time.Duration // Pre-parsed duration (TTL)
}

// RuleEngine manages parsing and evaluation of rules.
type RuleEngine struct {
	rules   atomic.Pointer[[]Rule]
	counter *Counter
}

// Env is the environment passed to the rule execution (Byte Mode Only).
type Env struct {
	IP      string
	Line    []byte // The raw log line
	Source  string // The source file
	Counter *Counter
	Addr    netip.Addr

	// Cache
	fields       []string
	fieldsParsed bool
}

var envPool = sync.Pool{
	New: func() interface{} {
		return &Env{
			fields: make([]string, 0, 16),
		}
	},
}

var (
	regexCache sync.Map
	regexCount int64
)

// Reset resets the environment for reuse.
func (e *Env) Reset() {
	e.IP = ""
	e.Line = nil
	e.Source = ""
	e.Counter = nil
	e.Addr = netip.Addr{}
	e.fields = e.fields[:0]
	e.fieldsParsed = false
}

// Fields returns []string for compatibility with expressions like Fields()[0] == "val".
func (e *Env) Fields() []string {
	if !e.fieldsParsed {
		// bytes.Fields returns [][]byte, convert to []string
		parts := bytes.Fields(e.Line)
		if cap(e.fields) < len(parts) {
			e.fields = make([]string, len(parts))
		} else {
			e.fields = e.fields[:len(parts)]
		}
		for i, part := range parts {
			e.fields[i] = string(part)
		}
		e.fieldsParsed = true
	}
	return e.fields
}

// Split returns []string for compatibility.
func (e *Env) Split(sep string) []string {
	parts := bytes.Split(e.Line, []byte(sep))
	res := make([]string, len(parts))
	for i, part := range parts {
		res[i] = string(part)
	}
	return res
}

// Get returns string for compatibility.
func (e *Env) Get(key string) string {
	keyBytes := []byte(key)
	idx := bytes.Index(e.Line, append(keyBytes, '='))
	if idx == -1 {
		idx = bytes.Index(e.Line, append(keyBytes, ':'))
		if idx == -1 {
			return ""
		}
		idx += len(key) + 1
	} else {
		idx += len(key) + 1
	}

	rest := e.Line[idx:]
	trimmed := bytes.TrimLeft(rest, " ")
	if len(trimmed) == 0 {
		return ""
	}

	if trimmed[0] == '"' {
		end := bytes.Index(trimmed[1:], []byte{'"'})
		if end == -1 {
			return string(trimmed[1:])
		}
		return string(trimmed[1 : end+1])
	}

	end := bytes.Index(trimmed, []byte{' '})
	if end == -1 {
		return string(trimmed)
	}
	return string(trimmed[:end])
}

func (e *Env) Count(window int) int {
	val := e.Counter.Count(e.Addr, window)
	fmt.Printf("DEBUG: Count(%s, %d) = %d\n", e.Addr, window, val)
	return val
}

// Time is an alias for Count(window)
func (e *Env) Time(window int) int {
	return e.Count(window)
}

// Log checks if the log line contains the given string (Case Insensitive).
// Usage: Log("failed")
func (e *Env) Log(pattern string) bool {
	return e.IContains(e.Line, pattern)
}

// LogE checks if the log line contains the given string (Case Sensitive / Exact).
// Usage: LogE("Failed")
func (e *Env) LogE(pattern string) bool {
	return bytes.Contains(e.Line, []byte(pattern))
}

// Msg checks if the log line contains the given string.
// Alias for Log(needle) - Case Insensitive
func (e *Env) Msg(needle string) bool {
	return e.Log(needle)
}

// Contains: haystack is []byte or string, needle is string.
func (e *Env) Contains(haystack interface{}, needle string) bool {
	switch h := haystack.(type) {
	case []byte:
		return bytes.Contains(h, []byte(needle))
	case string:
		return strings.Contains(h, needle)
	default:
		return false
	}
}

func (e *Env) IContains(haystack interface{}, needle string) bool {
	switch h := haystack.(type) {
	case []byte:
		return bytes.Contains(bytes.ToLower(h), bytes.ToLower([]byte(needle)))
	case string:
		return strings.Contains(strings.ToLower(h), strings.ToLower(needle))
	default:
		return false
	}
}

func (e *Env) Lower(v interface{}) string {
	switch val := v.(type) {
	case []byte:
		return string(bytes.ToLower(val))
	case string:
		return strings.ToLower(val)
	default:
		return ""
	}
}

func (e *Env) Int(v interface{}) int {
	var s string
	switch val := v.(type) {
	case string:
		s = val
	case []byte:
		s = string(val)
	default:
		return 0
	}
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}

func (e *Env) Like(haystack []byte, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return bytes.Contains(haystack, []byte(pattern))
	}

	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp).Match(haystack)
	}

	quoted := regexp.QuoteMeta(pattern)
	regexStr := strings.ReplaceAll(quoted, "\\*", ".*")
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return false
	}

	if atomic.LoadInt64(&regexCount) < 1000 {
		regexCache.Store(pattern, re)
		atomic.AddInt64(&regexCount, 1)
	}

	return re.Match(haystack)
}

func (e *Env) InCIDR(cidr string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return prefix.Contains(e.Addr)
}

// NewRuleEngine creates a new RuleEngine.
func NewRuleEngine(counter *Counter) *RuleEngine {
	re := &RuleEngine{
		counter: counter,
	}
	re.rules.Store(&[]Rule{})
	return re
}

// UpdateRules compiles and updates the current rules.
func (re *RuleEngine) UpdateRules(configs []types.LogEngineRule) error {
	var newRules []Rule
	for _, cfg := range configs {
		src := cfg.Expression

		// Generate expression if empty
		if src == "" {
			var andParts []string
			var orParts []string
			var notParts []string

			genMatch := func(pattern string) string {
				safeK := strings.ReplaceAll(pattern, "\"", "\\\"")
				if strings.Contains(pattern, "*") {
					quoted := regexp.QuoteMeta(pattern)
					regexStr := strings.ReplaceAll(quoted, "\\*", ".*")
					return fmt.Sprintf(`Line matches "%s"`, regexStr)
				}
				return fmt.Sprintf(`Contains(Line, "%s")`, safeK)
			}

			// 1. AND Logic
			allContains := append([]string{}, cfg.Keywords...)
			allContains = append(allContains, cfg.Contains...)
			allContains = append(allContains, cfg.Is...)
			allContains = append(allContains, cfg.And...)
			for _, k := range allContains {
				andParts = append(andParts, genMatch(k))
			}

			// 2. OR Logic
			allAny := append([]string{}, cfg.AnyContains...)
			allAny = append(allAny, cfg.Or...)
			for _, k := range allAny {
				orParts = append(orParts, genMatch(k))
			}

			// 3. NOT Logic
			allNot := append([]string{}, cfg.NotContains...)
			allNot = append(allNot, cfg.Not...)
			for _, k := range allNot {
				notParts = append(notParts, fmt.Sprintf("!%s", genMatch(k)))
			}

			// 4. Regex
			if cfg.Regex != "" {
				safeRe := strings.ReplaceAll(cfg.Regex, "\\", "\\\\")
				safeRe = strings.ReplaceAll(safeRe, "\"", "\\\"")
				andParts = append(andParts, fmt.Sprintf(`Line matches "%s"`, safeRe))
			}

			// Combine
			var sections []string
			if len(andParts) > 0 {
				sections = append(sections, fmt.Sprintf("(%s)", strings.Join(andParts, " && ")))
			}
			if len(orParts) > 0 {
				sections = append(sections, fmt.Sprintf("(%s)", strings.Join(orParts, " || ")))
			}
			if len(notParts) > 0 {
				sections = append(sections, strings.Join(notParts, " && "))
			}

			if len(sections) > 0 {
				src = strings.Join(sections, " && ")
			} else {
				src = "true"
			}
		}

		if cfg.Threshold > 0 {
			interval := cfg.Interval
			if interval <= 0 {
				interval = 60
			}
			src = fmt.Sprintf(`(%s) && Count(%d) > %d`, src, interval, cfg.Threshold)
		}

		// Preprocess expression to support lowercase aliases
		// We use regex to safely replace function calls without affecting string literals too much
		// Replacements:
		// log( -> Log(
		// logE( -> LogE(
		// msg( -> Msg(
		// time( -> Time(
		// count( -> Count(
		src = preprocessExpression(src)

		// Compile (always using Env)
		// Debug print
		fmt.Printf("Compiling Rule %s: %s\n", cfg.ID, src)
		program, err := expr.Compile(src, expr.Env(&Env{}))

		if err != nil {
			return fmt.Errorf("failed to compile rule '%s': %v (expr: %s)", cfg.ID, err, src)
		}

		// Parse Duration (TTL)
		// Prefer "ttl" field
		ttlStr := cfg.TTL
		ttl := time.Duration(0)
		if ttlStr != "" && ttlStr != "0" {
			if d, err := time.ParseDuration(ttlStr); err == nil {
				ttl = d
			} else {
				log.Printf("⚠️  Rule '%s': Invalid TTL '%s', using 0 (no expiry). Error: %v", cfg.ID, ttlStr, err)
			}
		}

		// Parse Action Type
		// 0/log -> Log (Default)
		// 1/dynamic/block -> Dynamic
		// 2/static/lock -> Static
		actStr := strings.ToLower(strings.TrimSpace(cfg.Action))
		var actType ActionType = ActionLog // Default to 0 (Log)

		switch actStr {
		case "", "0", "log": // Explicitly handle empty string as default (Log)
			actType = ActionLog
		case "1", "dynamic", "dynblock", "dynblack", "block", "black":
			actType = ActionDynamic
			// If ttl is missing, default to 0 (no expiry) or some default?
			// User said "action=1 can set ttl=10m, or not set let lru_hash auto eliminate".
			// So default 0 is correct.
		case "2", "static", "permanent", "lock", "deny":
			actType = ActionStatic
		default:
			// Fallback: Check if it looks like "block:10m" legacy format
			if strings.HasPrefix(actStr, "block:") || strings.HasPrefix(actStr, "black:") {
				actType = ActionDynamic
				// Try to parse duration from string if not set in Duration field
				if ttl == 0 {
					parts := strings.SplitN(actStr, ":", 2)
					if len(parts) == 2 {
						if d, err := time.ParseDuration(parts[1]); err == nil {
							ttl = d
						}
					}
				}
			} else {
				log.Printf("⚠️  Rule '%s': Unknown action '%s', defaulting to Log (0).", cfg.ID, cfg.Action)
				actType = ActionLog
			}
		}

		// Log compiled rule info for verification
		log.Printf("✅ Rule '%s' loaded: Action=%d (0=Log,1=Dyn,2=Sta), TTL=%v, Path=%s",
			cfg.ID, actType, ttl, cfg.Path)

		newRules = append(newRules, Rule{
			ID:         cfg.ID,
			Path:       cfg.Path,
			Source:     src,
			Program:    program,
			Action:     cfg.Action,
			ActionType: actType,
			TTL:        ttl,
		})
	}
	re.rules.Store(&newRules)
	return nil
}

// preprocessExpression replaces lowercase function aliases with their exported (TitleCase) counterparts.
// It uses regex to ensure only function calls are replaced.
func preprocessExpression(src string) string {
	// Map of lowercase alias -> Exported method name
	replacements := map[string]string{
		`\blog\(`:   "Log(",
		`\blogE\(`:  "LogE(",
		`\bmsg\(`:   "Msg(",
		`\btime\(`:  "Time(",
		`\bcount\(`: "Count(",
	}

	for pattern, replacement := range replacements {
		re := regexp.MustCompile(pattern)
		src = re.ReplaceAllString(src, replacement)
	}
	return src
}

func matchPath(pattern, source string) bool {
	if pattern == "" {
		return true
	}
	if pattern == source {
		return true
	}
	if !strings.Contains(pattern, "/") && !strings.Contains(pattern, "\\") {
		if filepath.Base(source) == pattern {
			return true
		}
	}
	matched, err := filepath.Match(pattern, source)
	if err == nil && matched {
		return true
	}
	return false
}

// Evaluate checks if the given IP matches any rule.
func (re *RuleEngine) Evaluate(ip netip.Addr, event LogEvent) (ActionType, time.Duration, string, bool) {
	rules := re.rules.Load()
	if rules == nil || len(*rules) == 0 {
		return ActionLog, 0, "", false
	}

	lineBytes := []byte(event.Line)
	env := envPool.Get().(*Env)
	defer func() {
		env.Reset()
		envPool.Put(env)
	}()

	env.IP = ip.String()
	env.Line = lineBytes
	env.Source = event.Source
	env.Counter = re.counter
	env.Addr = ip

	for _, rule := range *rules {
		if !matchPath(rule.Path, event.Source) {
			continue
		}

		output, err := expr.Run(rule.Program, env)
		if err != nil {
			continue
		}
		if matched, ok := output.(bool); ok && matched {
			return rule.ActionType, rule.TTL, rule.ID, true
		}
	}
	return ActionLog, 0, "", false
}
