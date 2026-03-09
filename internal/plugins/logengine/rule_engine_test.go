package logengine

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEnv_Fields tests Env Fields method
// TestEnv_Fields 测试 Env Fields 方法
func TestEnv_Fields(t *testing.T) {
	env := &Env{
		Line: []byte("field1 field2 field3"),
	}

	fields := env.Fields()
	assert.Equal(t, 3, len(fields))
	assert.Equal(t, "field1", fields[0])
	assert.Equal(t, "field2", fields[1])
	assert.Equal(t, "field3", fields[2])
}

// TestEnv_Split tests Env Split method
// TestEnv_Split 测试 Env Split 方法
func TestEnv_Split(t *testing.T) {
	env := &Env{
		Line: []byte("a,b,c"),
	}

	parts := env.Split(",")
	assert.Equal(t, 3, len(parts))
	assert.Equal(t, "a", parts[0])
	assert.Equal(t, "b", parts[1])
	assert.Equal(t, "c", parts[2])
}

// TestEnv_Get tests Env Get method
// TestEnv_Get 测试 Env Get 方法
func TestEnv_Get(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		key      string
		expected string
	}{
		{
			name:     "Key with equals",
			line:     `key1=value1 key2=value2`,
			key:      "key1",
			expected: "value1",
		},
		{
			name:     "Key with colon",
			line:     `key1: value1 key2: value2`,
			key:      "key1",
			expected: "value1",
		},
		{
			name:     "Quoted value",
			line:     `key1="quoted value" key2=value2`,
			key:      "key1",
			expected: "quoted value",
		},
		{
			name:     "Key not found",
			line:     `key1=value1`,
			key:      "key3",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &Env{Line: []byte(tt.line)}
			result := env.Get(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestEnv_JSON tests Env JSON method
// TestEnv_JSON 测试 Env JSON 方法
func TestEnv_JSON(t *testing.T) {
	t.Run("Valid JSON", func(t *testing.T) {
		env := &Env{Line: []byte(`{"key": "value", "number": 123}`)}
		result := env.JSON()
		assert.NotNil(t, result)
		assert.Equal(t, "value", result["key"])
		assert.Equal(t, float64(123), result["number"])
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		env := &Env{Line: []byte(`not a json`)}
		result := env.JSON()
		assert.Nil(t, result)
	})
}

// TestEnv_KV tests Env KV method
// TestEnv_KV 测试 Env KV 方法
func TestEnv_KV(t *testing.T) {
	t.Run("Key-Value pairs", func(t *testing.T) {
		env := &Env{Line: []byte(`key1=value1 key2=value2`)}
		result := env.KV()
		assert.Equal(t, "value1", result["key1"])
		assert.Equal(t, "value2", result["key2"])
	})

	t.Run("Colon separator", func(t *testing.T) {
		env := &Env{Line: []byte(`key1:value1 key2:value2`)}
		result := env.KV()
		assert.Equal(t, "value1", result["key1"])
		assert.Equal(t, "value2", result["key2"])
	})
}

// TestEnv_Match tests Env Match method
// TestEnv_Match 测试 Env Match 方法
func TestEnv_Match(t *testing.T) {
	env := &Env{Line: []byte(`192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1234`)}

	t.Run("Matching pattern", func(t *testing.T) {
		result := env.Match(`\d+\.\d+\.\d+\.\d+`)
		assert.True(t, result)
	})

	t.Run("Non-matching pattern", func(t *testing.T) {
		result := env.Match(`\d{5,}`)
		assert.False(t, result)
	})

	t.Run("Invalid regex", func(t *testing.T) {
		result := env.Match(`[invalid`)
		assert.False(t, result)
	})
}

// TestEnv_Log tests Env Log method
// TestEnv_Log 测试 Env Log 方法
func TestEnv_Log(t *testing.T) {
	env := &Env{Line: []byte(`Error: Connection failed from 192.168.1.1`)}

	t.Run("Case insensitive match", func(t *testing.T) {
		assert.True(t, env.Log("error"))
		assert.True(t, env.Log("ERROR"))
		assert.True(t, env.Log("Error"))
	})

	t.Run("No match", func(t *testing.T) {
		assert.False(t, env.Log("warning"))
	})
}

// TestEnv_LogE tests Env LogE method
// TestEnv_LogE 测试 Env LogE 方法
func TestEnv_LogE(t *testing.T) {
	env := &Env{Line: []byte(`Error: Connection failed`)}

	t.Run("Case sensitive match", func(t *testing.T) {
		assert.True(t, env.LogE("Error"))
		assert.False(t, env.LogE("error"))
	})
}

// TestEnv_Msg tests Env Msg method
// TestEnv_Msg 测试 Env Msg 方法
func TestEnv_Msg(t *testing.T) {
	env := &Env{Line: []byte(`Error: Connection failed`)}

	assert.True(t, env.Msg("error"))
	assert.True(t, env.Msg("failed"))
	assert.False(t, env.Msg("warning"))
}

// TestEnv_Contains tests Env Contains method
// TestEnv_Contains 测试 Env Contains 方法
func TestEnv_Contains(t *testing.T) {
	env := &Env{}

	t.Run("Byte slice", func(t *testing.T) {
		assert.True(t, env.Contains([]byte("hello world"), "world"))
		assert.False(t, env.Contains([]byte("hello world"), "foo"))
	})

	t.Run("String", func(t *testing.T) {
		assert.True(t, env.Contains("hello world", "world"))
		assert.False(t, env.Contains("hello world", "foo"))
	})
}

// TestEnv_IContains tests Env IContains method
// TestEnv_IContains 测试 Env IContains 方法
func TestEnv_IContains(t *testing.T) {
	env := &Env{}

	t.Run("Case insensitive byte slice", func(t *testing.T) {
		assert.True(t, env.IContains([]byte("HELLO WORLD"), "world"))
		assert.True(t, env.IContains([]byte("hello world"), "WORLD"))
	})

	t.Run("Case insensitive string", func(t *testing.T) {
		assert.True(t, env.IContains("HELLO WORLD", "world"))
		assert.True(t, env.IContains("hello world", "WORLD"))
	})
}

// TestEnv_Lower tests Env Lower method
// TestEnv_Lower 测试 Env Lower 方法
func TestEnv_Lower(t *testing.T) {
	env := &Env{}

	t.Run("Byte slice", func(t *testing.T) {
		result := env.Lower([]byte("HELLO"))
		assert.Equal(t, "hello", result)
	})

	t.Run("String", func(t *testing.T) {
		result := env.Lower("HELLO")
		assert.Equal(t, "hello", result)
	})
}

// TestEnv_Int tests Env Int method
// TestEnv_Int 测试 Env Int 方法
func TestEnv_Int(t *testing.T) {
	env := &Env{}

	tests := []struct {
		input    any
		expected int
	}{
		{"123", 123},
		{[]byte("456"), 456},
		{"not a number", 0},
		{123.45, 0},
	}

	for _, tt := range tests {
		result := env.Int(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

// TestEnv_Like tests Env Like method
// TestEnv_Like 测试 Env Like 方法
func TestEnv_Like(t *testing.T) {
	env := &Env{}

	t.Run("No wildcard", func(t *testing.T) {
		assert.True(t, env.Like([]byte("hello world"), "world"))
		assert.False(t, env.Like([]byte("hello world"), "foo"))
	})

	t.Run("With wildcard", func(t *testing.T) {
		assert.True(t, env.Like([]byte("hello world"), "hello*"))
		assert.True(t, env.Like([]byte("hello world"), "*world"))
		assert.True(t, env.Like([]byte("hello world"), "hello*world"))
	})
}

// TestEnv_InCIDR tests Env InCIDR method
// TestEnv_InCIDR 测试 Env InCIDR 方法
func TestEnv_InCIDR(t *testing.T) {
	addr, _ := netip.ParseAddr("192.168.1.100")
	env := &Env{Addr: addr}

	t.Run("IP in CIDR", func(t *testing.T) {
		assert.True(t, env.InCIDR("192.168.1.0/24"))
		assert.True(t, env.InCIDR("192.168.0.0/16"))
	})

	t.Run("IP not in CIDR", func(t *testing.T) {
		assert.False(t, env.InCIDR("10.0.0.0/8"))
	})

	t.Run("Invalid CIDR", func(t *testing.T) {
		assert.False(t, env.InCIDR("invalid"))
	})
}

// TestEnv_Reset tests Env Reset method
// TestEnv_Reset 测试 Env Reset 方法
func TestEnv_Reset(t *testing.T) {
	env := &Env{
		IP:     "192.168.1.1",
		Line:   []byte("test line"),
		Source: "test.log",
		Addr:   netip.Addr{},
	}

	env.Reset()

	assert.Equal(t, "", env.IP)
	assert.Nil(t, env.Line)
	assert.Equal(t, "", env.Source)
}

// TestMatchPath tests matchPath function
// TestMatchPath 测试 matchPath 函数
func TestMatchPath(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		source   string
		expected bool
	}{
		{"Empty pattern", "", "/var/log/test.log", true},
		{"Exact match", "/var/log/test.log", "/var/log/test.log", true},
		{"Basename match", "test.log", "/var/log/test.log", true},
		{"Wildcard match", "/var/log/*.log", "/var/log/test.log", true},
		{"No match", "other.log", "/var/log/test.log", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPath(tt.pattern, tt.source)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPreprocessExpression tests preprocessExpression function
// TestPreprocessExpression 测试 preprocessExpression 函数
func TestPreprocessExpression(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Lowercase log",
			input:    `log("test")`,
			expected: `Log("test")`,
		},
		{
			name:     "Lowercase msg",
			input:    `msg("test")`,
			expected: `Msg("test")`,
		},
		{
			name:     "Lowercase count",
			input:    `count(60) > 10`,
			expected: `Count(60) > 10`,
		},
		{
			name:     "Mixed functions",
			input:    `log("test") && count(60) > 10`,
			expected: `Log("test") && Count(60) > 10`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := preprocessExpression(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
