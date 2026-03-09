package logengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
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
	logger  sdk.Logger
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
	incremented  bool
}

var envPool = sync.Pool{
	New: func() any {
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
	e.incremented = false
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

// JSON parses the log line as JSON and returns a map.
// JSON 将日志行解析为 JSON 并返回一个 Map。
func (e *Env) JSON() map[string]any {
	var res map[string]any
	if err := json.Unmarshal(e.Line, &res); err != nil {
		return nil
	}
	return res
}

// KV parses the log line as Key-Value pairs (e.g., "key1=val1 key2=val2") and returns a map.
// KV 将日志行解析为键值对（例如 "key1=val1 key2=val2"）并返回一个 Map。
func (e *Env) KV() map[string]string {
	res := make(map[string]string)
	parts := bytes.Fields(e.Line)
	for _, part := range parts {
		kv := bytes.SplitN(part, []byte{'='}, 2)
		if len(kv) == 2 {
			res[string(kv[0])] = string(kv[1])
		} else {
			kv = bytes.SplitN(part, []byte{':'}, 2)
			if len(kv) == 2 {
				res[string(kv[0])] = string(kv[1])
			}
		}
	}
	return res
}

// Match checks if the log line matches the given regular expression.
// Match 检查日志行是否匹配给定的正则表达式。
func (e *Env) Match(pattern string) bool {
	re, ok := regexCache.Load(pattern)
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			logger.Get(nil).Warnf("[WARN]  Invalid regex pattern: %s", pattern)
			return false
		}
		regexCache.Store(pattern, re)
		atomic.AddInt64(&regexCount, 1)
	}
	regex, ok := re.(*regexp.Regexp)
	if !ok {
		return false
	}
	return regex.Match(e.Line)
}

func (e *Env) Count(window int) int {
	if !e.incremented {
		e.Counter.Inc(e.Addr)
		e.incremented = true
	}
	val := e.Counter.Count(e.Addr, window)
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
func (e *Env) Contains(haystack any, needle string) bool {
	switch h := haystack.(type) {
	case []byte:
		return bytes.Contains(h, []byte(needle))
	case string:
		return strings.Contains(h, needle)
	default:
		return false
	}
}

func (e *Env) IContains(haystack any, needle string) bool {
	switch h := haystack.(type) {
	case []byte:
		return bytes.Contains(bytes.ToLower(h), bytes.ToLower([]byte(needle)))
	case string:
		return strings.Contains(strings.ToLower(h), strings.ToLower(needle))
	default:
		return false
	}
}

func (e *Env) Lower(v any) string {
	switch val := v.(type) {
	case []byte:
		return string(bytes.ToLower(val))
	case string:
		return strings.ToLower(val)
	default:
		return ""
	}
}

func (e *Env) Int(v any) int {
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
	if _, err := fmt.Sscanf(s, "%d", &i); err != nil {
		return 0
	}
	return i
}

func (e *Env) Like(haystack []byte, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return bytes.Contains(haystack, []byte(pattern))
	}

	if v, ok := regexCache.Load(pattern); ok {
		regex, ok := v.(*regexp.Regexp)
		if !ok {
			return false
		}
		return regex.Match(haystack)
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
func NewRuleEngine(counter *Counter, logger sdk.Logger) *RuleEngine {
	re := &RuleEngine{
		counter: counter,
		logger:  logger,
	}
	re.rules.Store(&[]Rule{})
	return re
}

// UpdateRules compiles and updates the current rules.
func (re *RuleEngine) UpdateRules(configs []types.LogEngineRule) error {
	newRules := make([]Rule, 0, len(configs))
	for i := range configs {
		rule, err := re.compileRule(configs[i])
		if err != nil {
			return err
		}
		newRules = append(newRules, rule)
	}
	re.rules.Store(&newRules)
	return nil
}

// compileRule compiles a single rule from configuration.
// compileRule 从配置编译单个规则。
func (re *RuleEngine) compileRule(cfg types.LogEngineRule) (Rule, error) {
	src := cfg.Expression
	if src == "" {
		src = re.generateExpression(cfg)
	}

	if cfg.Threshold > 0 {
		interval := cfg.Interval
		if interval <= 0 {
			interval = 60
		}
		src = fmt.Sprintf(`(%s) && Count(%d) > %d`, src, interval, cfg.Threshold)
	}

	src = preprocessExpression(src)
	logger.Get(nil).Debugf("Compiling Rule %s: %s", cfg.ID, src)
	program, err := expr.Compile(src, expr.Env(&Env{}))
	if err != nil {
		return Rule{}, fmt.Errorf("failed to compile rule '%s': %v (expr: %s)", cfg.ID, err, src)
	}

	ttl := re.parseTTL(cfg)
	actType := re.parseActionType(cfg)

	re.logger.Infof("[OK] Rule '%s' loaded: Action=%d (0=Log,1=Dyn,2=Sta), TTL=%v, Path=%s",
		cfg.ID, actType, ttl, cfg.Path)

	return Rule{
		ID:         cfg.ID,
		Path:       cfg.Path,
		Source:     src,
		Program:    program,
		Action:     cfg.Action,
		ActionType: actType,
		TTL:        ttl,
	}, nil
}

// generateExpression generates an expression from rule configuration.
// generateExpression 从规则配置生成表达式。
func (re *RuleEngine) generateExpression(cfg types.LogEngineRule) string {
	totalLen := len(cfg.Keywords) + len(cfg.Contains) + len(cfg.Is) + len(cfg.And) +
		len(cfg.AnyContains) + len(cfg.Or) + len(cfg.NotContains) + len(cfg.Not)
	if cfg.Regex != "" {
		totalLen++
	}

	andParts := make([]string, 0, totalLen)
	orParts := make([]string, 0, len(cfg.AnyContains)+len(cfg.Or))
	notParts := make([]string, 0, len(cfg.NotContains)+len(cfg.Not))

	genMatch := func(pattern string) string {
		if strings.Contains(pattern, "*") {
			quoted := regexp.QuoteMeta(pattern)
			regexStr := strings.ReplaceAll(quoted, "\\*", ".*")
			return fmt.Sprintf(`Line matches %q`, regexStr)
		}
		return fmt.Sprintf(`Contains(Line, %q)`, pattern)
	}

	allContains := append([]string{}, cfg.Keywords...)
	allContains = append(allContains, cfg.Contains...)
	allContains = append(allContains, cfg.Is...)
	allContains = append(allContains, cfg.And...)
	for _, k := range allContains {
		andParts = append(andParts, genMatch(k))
	}

	allAny := append([]string{}, cfg.AnyContains...)
	allAny = append(allAny, cfg.Or...)
	for _, k := range allAny {
		orParts = append(orParts, genMatch(k))
	}

	allNot := append([]string{}, cfg.NotContains...)
	allNot = append(allNot, cfg.Not...)
	for _, k := range allNot {
		notParts = append(notParts, fmt.Sprintf("!%s", genMatch(k)))
	}

	if cfg.Regex != "" {
		andParts = append(andParts, fmt.Sprintf(`Line matches %q`, cfg.Regex))
	}

	return combineExpressionParts(andParts, orParts, notParts)
}

// combineExpressionParts combines expression parts into a single expression.
// combineExpressionParts 将表达式部分组合成单个表达式。
func combineExpressionParts(andParts, orParts, notParts []string) string {
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
		return strings.Join(sections, " && ")
	}
	return "true"
}

// parseTTL parses the TTL duration from configuration.
// parseTTL 从配置解析 TTL 持续时间。
func (re *RuleEngine) parseTTL(cfg types.LogEngineRule) time.Duration {
	ttlStr := cfg.TTL
	if ttlStr == "" || ttlStr == "0" {
		return 0
	}

	d, err := time.ParseDuration(ttlStr)
	if err != nil {
		re.logger.Warnf("[WARN]  Rule '%s': Invalid TTL '%s', using 0 (no expiry). Error: %v", cfg.ID, ttlStr, err)
		return 0
	}
	return d
}

// parseActionType parses the action type from configuration.
// parseActionType 从配置解析动作类型。
func (re *RuleEngine) parseActionType(cfg types.LogEngineRule) ActionType {
	actStr := strings.ToLower(strings.TrimSpace(cfg.Action))

	switch actStr {
	case "", "0", "log":
		return ActionLog
	case "1", "dynamic", "dynblock", "dynblack", "block", "black":
		return ActionDynamic
	case "2", "static", "deny", "lock", "permanent", "blacklist":
		return ActionStatic
	default:
		return re.parseLegacyActionType(cfg, actStr)
	}
}

// parseLegacyActionType parses legacy action type format.
// parseLegacyActionType 解析旧版动作类型格式。
func (re *RuleEngine) parseLegacyActionType(cfg types.LogEngineRule, actStr string) ActionType {
	if strings.HasPrefix(actStr, "block:") || strings.HasPrefix(actStr, "black:") {
		return ActionDynamic
	}

	re.logger.Warnf("[WARN]  Rule '%s': Unknown action '%s', defaulting to Log (0).", cfg.ID, cfg.Action)
	return ActionLog
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
	env, ok := envPool.Get().(*Env)
	if !ok || env == nil {
		env = &Env{}
	}
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
