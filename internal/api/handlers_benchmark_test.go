package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/livp123/netxfw/pkg/sdk/mock"
)

// BenchmarkHandleHealth benchmarks health handler.
// BenchmarkHandleHealth 基准测试健康检查处理器。
func BenchmarkHandleHealth(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/health", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkHandleStats benchmarks stats handler.
// BenchmarkHandleStats 基准测试统计处理器。
func BenchmarkHandleStats(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/stats", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkHandleConfig benchmarks config handler.
// BenchmarkHandleConfig 基准测试配置处理器。
func BenchmarkHandleConfig(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/config", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkHandleVersion benchmarks version handler.
// BenchmarkHandleVersion 基准测试版本处理器。
func BenchmarkHandleVersion(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/version", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkHandleConntrack benchmarks conntrack handler.
// BenchmarkHandleConntrack 基准测试连接跟踪处理器。
func BenchmarkHandleConntrack(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)
	mock.SetupMockConntrack(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/conntrack", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkJSONEncoding benchmarks JSON encoding for API responses.
// BenchmarkJSONEncoding 基准测试 API 响应的 JSON 编码。
func BenchmarkJSONEncoding(b *testing.B) {
	response := map[string]any{
		"success": true,
		"message": "Operation completed",
		"data": map[string]any{
			"ip":      "192.168.1.1",
			"action":  "blocked",
			"count":   100,
			"enabled": true,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(response)
	}
}

// BenchmarkJSONDecoding benchmarks JSON decoding for API requests.
// BenchmarkJSONDecoding 基准测试 API 请求的 JSON 解码。
func BenchmarkJSONDecoding(b *testing.B) {
	data := []byte(`{"ip":"192.168.1.1","action":"block","port":80}`)
	var req struct {
		IP     string `json:"ip"`
		Action string `json:"action"`
		Port   int    `json:"port"`
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = json.Unmarshal(data, &req)
	}
}

// BenchmarkServer_MultipleEndpoints benchmarks multiple endpoint routing.
// BenchmarkServer_MultipleEndpoints 基准测试多端点路由。
func BenchmarkServer_MultipleEndpoints(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/stats"},
		{"GET", "/health"},
		{"GET", "/version"},
		{"GET", "/api/config"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		endpoint := endpoints[i%len(endpoints)]
		req := httptest.NewRequest(endpoint.method, endpoint.path, http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkConcurrentAPIRequests benchmarks concurrent API requests.
// BenchmarkConcurrentAPIRequests 基准测试并发 API 请求。
func BenchmarkConcurrentAPIRequests(b *testing.B) {
	s := mock.NewMockSDK()
	mock.SetupMockStats(s)

	server := NewServer(s, 8080)
	handler := server.Handler()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			var req *http.Request
			switch i % 4 {
			case 0:
				req = httptest.NewRequest("GET", "/api/stats", http.NoBody)
			case 1:
				req = httptest.NewRequest("GET", "/health", http.NoBody)
			case 2:
				req = httptest.NewRequest("GET", "/version", http.NoBody)
			case 3:
				req = httptest.NewRequest("GET", "/api/config", http.NoBody)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			i++
		}
	})
}
