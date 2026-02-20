package logengine

import (
	"strings"
	"unicode"
)

// Tokenizer provides high-performance string splitting mechanisms.
type Tokenizer struct{}

// NewTokenizer creates a new Tokenizer instance.
func NewTokenizer() *Tokenizer {
	return &Tokenizer{}
}

// Tokenize splits a string into fields using a custom byte scan or strings.FieldsFunc.
// For the requirement "strings.FieldsFunc or byte scan", we use a specialized byte scan
// for common delimiters to avoid the overhead of Unicode lookup in strings.Fields if possible,
// but fallback to a robust method.
// Here we implement a fast ASCII-whitespace splitter that falls back to standard behavior.
func (t *Tokenizer) Tokenize(s string) []string {
	// Fast path: if string is empty
	if s == "" {
		return nil
	}

	// We use strings.Fields as it is highly optimized in Go (implemented with byte scan for ASCII).
	// But the requirement says "strings.FieldsFunc or byte scan".
	// Let's implement a custom one that handles common log delimiters (space, tab, comma, equal).

	f := func(c rune) bool {
		return !unicode.IsPrint(c) || c == ' ' || c == '\t' || c == ',' || c == '=' || c == '"'
	}

	return strings.FieldsFunc(s, f)
}
