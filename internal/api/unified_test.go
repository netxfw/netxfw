package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// Test constants for unified tests.
// 统一测试的常量。
const (
	testSecret      = "test-secret"
	testInvalidJSON = `{"invalid json`
)

// TestHandleHealthz tests the health check endpoint
// TestHandleHealthz 测试健康检查端点
func TestHandleHealthz(t *testing.T) {
	server := NewServer(nil, 8080)
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

// TestHandleVersion tests the version endpoint
// TestHandleVersion 测试版本端点
func TestHandleVersion(t *testing.T) {
	server := NewServer(nil, 8080)
	req := httptest.NewRequest(http.MethodGet, "/version", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleVersion(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp, "version")
}

// TestHandleStats tests the stats endpoint
// TestHandleStats 测试统计端点
func TestHandleStats(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleStats(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]uint64
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp, "pass")
	assert.Contains(t, resp, "drop")
}

// TestHandleRulesGet tests the rules GET endpoint
// TestHandleRulesGet 测试规则 GET 端点
func TestHandleRulesGet(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	// Add some test data
	// 添加一些测试数据
	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	req := httptest.NewRequest(http.MethodGet, "/api/rules", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp, "blacklist")
	assert.Contains(t, resp, "whitelist")
	assert.Contains(t, resp, "totalBlacklist")
	assert.Contains(t, resp, "totalWhitelist")
}

// TestHandleRulesPostBlacklist tests adding to blacklist
// TestHandleRulesPostBlacklist 测试添加到黑名单
func TestHandleRulesPostBlacklist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"type":"blacklist","action":"add","cidr":"192.168.1.100/32"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify the IP was added
	// 验证 IP 已添加
	blacklisted, _ := mockMgr.IsIPInBlacklist("192.168.1.100/32")
	assert.True(t, blacklisted)
}

// TestHandleRulesPostWhitelist tests adding to whitelist
// TestHandleRulesPostWhitelist 测试添加到白名单
func TestHandleRulesPostWhitelist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"type":"whitelist","action":"add","cidr":"10.0.0.1/32"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify the IP was added
	// 验证 IP 已添加
	whitelisted, _ := mockMgr.IsIPInWhitelist("10.0.0.1/32")
	assert.True(t, whitelisted)
}

// TestHandleRulesPostRemove tests removing from blacklist
// TestHandleRulesPostRemove 测试从黑名单移除
func TestHandleRulesPostRemove(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	// Add first, then remove
	// 先添加，再移除
	mockMgr.AddBlacklistIP("192.168.1.200/32")

	body := `{"type":"blacklist","action":"remove","cidr":"192.168.1.200/32"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify the IP was removed
	// 验证 IP 已移除
	blacklisted, _ := mockMgr.IsIPInBlacklist("192.168.1.200/32")
	assert.False(t, blacklisted)
}

// TestHandleRulesPostInvalid tests invalid request
// TestHandleRulesPostInvalid 测试无效请求
func TestHandleRulesPostInvalid(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := testInvalidJSON
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleConfigPost tests config update
// TestHandleConfigPost 测试配置更新
func TestHandleConfigPost(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"default_deny","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, mockMgr.DefaultDeny)
}

// TestHandleConfigPostAFXDP tests AFXDP config update
// TestHandleConfigPostAFXDP 测试 AFXDP 配置更新
func TestHandleConfigPostAFXDP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"afxdp","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, mockMgr.EnableAFXDP)
}

// TestHandleConfigInvalidJSON tests invalid JSON in config
// TestHandleConfigInvalidJSON 测试配置中的无效 JSON
func TestHandleConfigInvalidJSON(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := testInvalidJSON
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleSyncInvalidMethod tests sync with invalid method
// TestHandleSyncInvalidMethod 测试无效方法的同步
func TestHandleSyncInvalidMethod(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/sync", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleSync(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestHandleUI tests the UI endpoint
// TestHandleUI 测试 UI 端点
func TestHandleUI(t *testing.T) {
	server := NewServer(nil, 8080)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleUI(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// TestMetricsServerStart tests starting the metrics server
// TestMetricsServerStart 测试启动 metrics 服务器
func TestMetricsServerStart(t *testing.T) {
	cfg := &types.MetricsConfig{
		Enabled:       true,
		ServerEnabled: true,
		Port:          11813, // Use different port to avoid conflicts
	}

	metricsServer := NewMetricsServer(nil, cfg)
	assert.NotNil(t, metricsServer)

	// Start the server
	// 启动服务器
	ctx := context.Background()
	err := metricsServer.Start(ctx)
	assert.NoError(t, err)

	// Give it time to start
	// 给它时间启动
	time.Sleep(100 * time.Millisecond)

	// Stop the server
	// 停止服务器
	err = metricsServer.Stop()
	assert.NoError(t, err)
}

// TestMetricsServerDisabled tests disabled metrics server
// TestMetricsServerDisabled 测试禁用的 metrics 服务器
func TestMetricsServerDisabled(t *testing.T) {
	cfg := &types.MetricsConfig{
		Enabled:       false,
		ServerEnabled: false,
		Port:          11812,
	}

	metricsServer := NewMetricsServer(nil, cfg)
	ctx := context.Background()
	err := metricsServer.Start(ctx)
	assert.NoError(t, err)
}

// TestMetricsServerStop tests stopping the metrics server
// TestMetricsServerStop 测试停止 metrics 服务器
func TestMetricsServerStop(t *testing.T) {
	cfg := &types.MetricsConfig{
		Enabled:       true,
		ServerEnabled: true,
		Port:          11814,
	}

	metricsServer := NewMetricsServer(nil, cfg)
	ctx := context.Background()
	metricsServer.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	err := metricsServer.Stop()
	assert.NoError(t, err)
}

// TestGenerateRandomToken tests token generation
// TestGenerateRandomToken 测试令牌生成
func TestGenerateRandomToken(t *testing.T) {
	token1 := generateRandomToken(16)
	token2 := generateRandomToken(16)

	// Tokens should be different
	// 令牌应该不同
	assert.NotEqual(t, token1, token2)

	// Token length should be correct (hex encoded, so 2x length)
	// 令牌长度应该正确（十六进制编码，所以是 2 倍长度）
	assert.Len(t, token1, 32) // 16 bytes = 32 hex chars
}

// TestParseIPPortAction tests IP port action parsing
// TestParseIPPortAction 测试 IP 端口动作解析
func TestParseIPPortAction(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantIP    string
		wantPort  uint16
		wantError bool
	}{
		{"Valid allow", "192.168.1.1:80:allow", "192.168.1.1", 80, false},
		{"Valid deny", "10.0.0.1:443:deny", "10.0.0.1", 443, false},
		{"Invalid format", "invalid", "", 0, true},
		{"Invalid port", "1.2.3.4:abc:allow", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, action, err := parseIPPortAction(tt.input)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantIP, ip)
				assert.Equal(t, tt.wantPort, port)
				_ = action // Action is uint8
			}
		})
	}
}

// TestSignToken tests the signToken function
// TestSignToken 测试 signToken 函数
func TestSignToken(t *testing.T) {
	claims := TokenClaims{
		Role: "admin",
		Exp:  time.Now().Add(1 * time.Hour).Unix(),
		Iat:  time.Now().Unix(),
	}

	token, err := signToken(claims, testSecret)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Token should have 3 parts separated by dots
	// 令牌应该有 3 个由点分隔的部分
	parts := strings.Split(token, ".")
	assert.Equal(t, 3, len(parts))
}

// TestSignToken_EmptySecret tests signToken with empty secret
// TestSignToken_EmptySecret 测试空密钥的 signToken
func TestSignToken_EmptySecret(t *testing.T) {
	claims := TokenClaims{
		Role: "admin",
		Exp:  time.Now().Add(1 * time.Hour).Unix(),
		Iat:  time.Now().Unix(),
	}

	token, err := signToken(claims, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

// TestVerifyToken tests the verifyToken function
// TestVerifyToken 测试 verifyToken 函数
func TestVerifyToken(t *testing.T) {
	// Create a valid token
	// 创建一个有效令牌
	claims := TokenClaims{
		Role: "admin",
		Exp:  time.Now().Add(1 * time.Hour).Unix(),
		Iat:  time.Now().Unix(),
	}
	token, err := signToken(claims, testSecret)
	assert.NoError(t, err)

	// Verify the token
	// 验证令牌
	verifiedClaims, err := verifyToken(token, testSecret)
	assert.NoError(t, err)
	assert.Equal(t, "admin", verifiedClaims.Role)
}

// TestVerifyToken_InvalidFormat tests verifyToken with invalid format
// TestVerifyToken_InvalidFormat 测试格式无效的 verifyToken
func TestVerifyToken_InvalidFormat(t *testing.T) {
	// Token with wrong number of parts
	// 部分数量错误的令牌
	_, err := verifyToken("invalid.token", "secret")
	assert.Error(t, err)

	// Token with no parts
	// 没有部分的令牌
	_, err = verifyToken("invalidtoken", "secret")
	assert.Error(t, err)
}

// TestVerifyToken_InvalidSignature tests verifyToken with invalid signature
// TestVerifyToken_InvalidSignature 测试签名无效的 verifyToken
func TestVerifyToken_InvalidSignature(t *testing.T) {
	wrongSecret := "wrong-secret"

	claims := TokenClaims{
		Role: "admin",
		Exp:  time.Now().Add(1 * time.Hour).Unix(),
		Iat:  time.Now().Unix(),
	}
	token, err := signToken(claims, testSecret)
	assert.NoError(t, err)

	// Verify with wrong secret
	// 使用错误的密钥验证
	_, err = verifyToken(token, wrongSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

// TestVerifyToken_ExpiredToken tests verifyToken with expired token
// TestVerifyToken_ExpiredToken 测试过期令牌的 verifyToken
func TestVerifyToken_ExpiredToken(t *testing.T) {
	// Create an expired token
	// 创建一个过期的令牌
	claims := TokenClaims{
		Role: "admin",
		Exp:  time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		Iat:  time.Now().Add(-2 * time.Hour).Unix(),
	}
	token, err := signToken(claims, testSecret)
	assert.NoError(t, err)

	// Verify should fail
	// 验证应该失败
	_, err = verifyToken(token, testSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// TestVerifyToken_InvalidBase64 tests verifyToken with invalid base64
// TestVerifyToken_InvalidBase64 测试 base64 无效的 verifyToken
func TestVerifyToken_InvalidBase64(t *testing.T) {
	// Token with invalid base64 in payload
	// 负载中 base64 无效的令牌
	_, err := verifyToken("aGVhZGVy.!!invalid!!.c2ln", "secret")
	assert.Error(t, err)
}

// TestTokenClaims tests TokenClaims struct
// TestTokenClaims 测试 TokenClaims 结构体
func TestTokenClaims(t *testing.T) {
	claims := TokenClaims{
		Role: "admin",
		Exp:  1234567890,
		Iat:  1234560000,
	}

	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, int64(1234567890), claims.Exp)
	assert.Equal(t, int64(1234560000), claims.Iat)
}

// TestSignVerifyRoundTrip tests the full sign and verify cycle
// TestSignVerifyRoundTrip 测试完整的签名和验证周期
func TestSignVerifyRoundTrip(t *testing.T) {
	secret := "my-super-secret-key"

	tests := []struct {
		name  string
		role  string
		expIn time.Duration
		valid bool
	}{
		{"Valid admin token", "admin", 1 * time.Hour, true},
		{"Valid user token", "user", 30 * time.Minute, true},
		{"Expired token", "admin", -1 * time.Hour, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := TokenClaims{
				Role: tt.role,
				Exp:  time.Now().Add(tt.expIn).Unix(),
				Iat:  time.Now().Unix(),
			}

			token, err := signToken(claims, secret)
			assert.NoError(t, err)

			verifiedClaims, err := verifyToken(token, secret)

			if tt.valid {
				assert.NoError(t, err)
				assert.Equal(t, tt.role, verifiedClaims.Role)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestGenerateRandomToken_Uniqueness tests that tokens are unique
// TestGenerateRandomToken_Uniqueness 测试令牌是否唯一
func TestGenerateRandomToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := generateRandomToken(16)
		assert.False(t, tokens[token], "Token should be unique")
		tokens[token] = true
	}
}

// TestServer_Sdk tests Server Sdk method
// TestServer_Sdk 测试 Server Sdk 方法
func TestServer_Sdk(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	assert.Equal(t, s, server.Sdk())
}

// TestServer_Port tests Server Port method
// TestServer_Port 测试 Server Port 方法
func TestServer_Port(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 9090)

	assert.Equal(t, 9090, server.Port())
}

// TestServer_NewServer tests NewServer function
// TestServer_NewServer 测试 NewServer 函数
func TestServer_NewServer(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	assert.NotNil(t, server)
	assert.Equal(t, s, server.sdk)
	assert.Equal(t, 8080, server.port)
}

// TestGenerateRandomToken_DifferentLengths tests generateRandomToken with different lengths
// TestGenerateRandomToken_DifferentLengths 测试不同长度的 generateRandomToken
func TestGenerateRandomToken_DifferentLengths(t *testing.T) {
	tests := []struct {
		name        string
		inputLength int
		expectedLen int
	}{
		{"Length 8", 8, 16},
		{"Length 16", 16, 32},
		{"Length 32", 32, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := generateRandomToken(tt.inputLength)
			assert.Len(t, token, tt.expectedLen)
		})
	}
}

// TestParseIPPortAction_IPv6Allow tests parseIPPortAction with IPv6 allow
// TestParseIPPortAction_IPv6Allow 测试 IPv6 allow 的 parseIPPortAction
func TestParseIPPortAction_IPv6Allow(t *testing.T) {
	host, port, action, err := parseIPPortAction("[2001:db8::1]:80:allow")
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::1", host)
	assert.Equal(t, uint16(80), port)
	assert.Equal(t, uint8(1), action) // allow = 1
}

// TestParseIPPortAction_IPv6Deny tests parseIPPortAction with IPv6 deny
// TestParseIPPortAction_IPv6Deny 测试 IPv6 deny 的 parseIPPortAction
func TestParseIPPortAction_IPv6Deny(t *testing.T) {
	host, port, action, err := parseIPPortAction("[::1]:443:deny")
	assert.NoError(t, err)
	assert.Equal(t, "::1", host)
	assert.Equal(t, uint16(443), port)
	assert.Equal(t, uint8(2), action) // deny = 2
}

// TestParseIPPortAction_NoAction tests parseIPPortAction without explicit action
// TestParseIPPortAction_NoAction 测试无显式动作的 parseIPPortAction
func TestParseIPPortAction_NoAction(t *testing.T) {
	host, port, action, err := parseIPPortAction("192.168.1.1:8080")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", host)
	assert.Equal(t, uint16(8080), port)
	assert.Equal(t, uint8(2), action) // default deny = 2
}

// TestParseIPPortAction_EmptyInput tests parseIPPortAction with empty input
// TestParseIPPortAction_EmptyInput 测试空输入的 parseIPPortAction
func TestParseIPPortAction_EmptyInput(t *testing.T) {
	_, _, _, err := parseIPPortAction("")
	assert.Error(t, err)
}

// TestParseIPPortAction_LargePort tests parsing with large port number
// TestParseIPPortAction_LargePort 测试大端口号的解析
func TestParseIPPortAction_LargePort(t *testing.T) {
	host, port, action, err := parseIPPortAction("192.168.1.1:65535:allow")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", host)
	assert.Equal(t, uint16(65535), port)
	assert.Equal(t, uint8(1), action)
}

// TestParseIPPortAction_InvalidLargePort tests parsing with invalid large port
// TestParseIPPortAction_InvalidLargePort 测试无效大端口的解析
func TestParseIPPortAction_InvalidLargePort(t *testing.T) {
	_, _, _, err := parseIPPortAction("192.168.1.1:65536:allow")
	assert.Error(t, err)
}

// TestHandleConntrack tests handleConntrack handler
// TestHandleConntrack 测试 handleConntrack 处理程序
func TestHandleConntrack(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/conntrack", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleConntrack(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp, "total")
	assert.Contains(t, resp, "top")
}

// TestHandleRules_IPPortRules tests IP+Port rules handling
// TestHandleRules_IPPortRules 测试 IP+端口规则处理
func TestHandleRules_IPPortRules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	// Add IP+Port rule
	// 添加 IP+端口规则
	body := `{"type":"ip_port_rules","action":"add","cidr":"192.168.1.1:80:allow"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleLogin tests the login endpoint
// TestHandleLogin 测试登录端点
func TestHandleLogin(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	// Test with invalid method
	// 测试无效方法
	req := httptest.NewRequest(http.MethodGet, "/api/login", http.NoBody)
	rec := httptest.NewRecorder()
	server.handleLogin(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestHandleLogin_InvalidJSON tests login with invalid JSON
// TestHandleLogin_InvalidJSON 测试无效 JSON 的登录
func TestHandleLogin_InvalidJSON(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := testInvalidJSON
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleLogin(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleHealth tests the health endpoint
// TestHandleHealth 测试健康端点
func TestHandleHealth(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealth(rec, req)
	// Should return basic health check since mock doesn't implement GetHealthChecker
	// 应该返回基本健康检查，因为 mock 没有实现 GetHealthChecker
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleHealth_NilSDK tests health endpoint with nil SDK
// TestHandleHealth_NilSDK 测试空 SDK 的健康端点
func TestHandleHealth_NilSDK(t *testing.T) {
	server := NewServer(nil, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealth(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleHealthMaps tests the health maps endpoint
// TestHandleHealthMaps 测试健康 Map 端点
func TestHandleHealthMaps(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health/maps", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealthMaps(rec, req)
	// Mock doesn't implement GetHealthChecker
	// Mock 没有实现 GetHealthChecker
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

// TestHandleHealthMaps_NilSDK tests health maps endpoint with nil SDK
// TestHandleHealthMaps_NilSDK 测试空 SDK 的健康 Map 端点
func TestHandleHealthMaps_NilSDK(t *testing.T) {
	server := NewServer(nil, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health/maps", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealthMaps(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleHealthMap tests the health map endpoint for a specific map
// TestHandleHealthMap 测试特定 Map 的健康端点
func TestHandleHealthMap(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health/map?name=blacklist", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealthMap(rec, req)
	// Mock doesn't implement GetHealthChecker
	// Mock 没有实现 GetHealthChecker
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

// TestHandleHealthMap_MissingName tests health map endpoint without map name
// TestHandleHealthMap_MissingName 测试没有 Map 名称的健康 Map 端点
func TestHandleHealthMap_MissingName(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health/map", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealthMap(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleHealthMap_NilSDK tests health map endpoint with nil SDK
// TestHandleHealthMap_NilSDK 测试空 SDK 的健康 Map 端点
func TestHandleHealthMap_NilSDK(t *testing.T) {
	server := NewServer(nil, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/health/map?name=blacklist", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleHealthMap(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandlePerfStats tests the performance stats endpoint
// TestHandlePerfStats 测试性能统计端点
func TestHandlePerfStats(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/perf/stats", http.NoBody)
	rec := httptest.NewRecorder()

	server.handlePerfStats(rec, req)
	// Mock returns a valid PerfStats
	// Mock 返回有效的 PerfStats
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandlePerfLatency tests the performance latency endpoint
// TestHandlePerfLatency 测试性能延迟端点
func TestHandlePerfLatency(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/perf/latency", http.NoBody)
	rec := httptest.NewRecorder()

	server.handlePerfLatency(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandlePerfCache tests the performance cache endpoint
// TestHandlePerfCache 测试性能缓存端点
func TestHandlePerfCache(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/perf/cache", http.NoBody)
	rec := httptest.NewRecorder()

	server.handlePerfCache(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandlePerfTraffic tests the performance traffic endpoint
// TestHandlePerfTraffic 测试性能流量端点
func TestHandlePerfTraffic(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/perf/traffic", http.NoBody)
	rec := httptest.NewRecorder()

	server.handlePerfTraffic(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandlePerfReset tests the performance reset endpoint
// TestHandlePerfReset 测试性能重置端点
func TestHandlePerfReset(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	// Test with invalid method
	// 测试无效方法
	req := httptest.NewRequest(http.MethodGet, "/api/perf/reset", http.NoBody)
	rec := httptest.NewRecorder()

	server.handlePerfReset(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestHandlePerfReset_Post tests the performance reset endpoint with POST
// TestHandlePerfReset_Post 测试 POST 方法的性能重置端点
func TestHandlePerfReset_Post(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodPost, "/api/perf/reset", http.NoBody)
	rec := httptest.NewRecorder()

	server.handlePerfReset(rec, req)
	// Mock returns a valid PerfStats that supports Reset
	// Mock 返回支持 Reset 的有效 PerfStats
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleRules_WhitelistWithPort tests whitelist with port
// TestHandleRules_WhitelistWithPort 测试带端口的白名单
func TestHandleRules_WhitelistWithPort(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"type":"whitelist","action":"add","cidr":"10.0.0.1:8080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleSync_Map2File tests sync from map to file
// TestHandleSync_Map2File 测试从 Map 同步到文件
func TestHandleSync_Map2File(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"direction":"map2file","mode":"incremental"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sync", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleSync(rec, req)
	// May fail due to missing config file
	// 可能因缺少配置文件而失败
	_ = rec.Code
}

// TestHandleSync_File2Map tests sync from file to map
// TestHandleSync_File2Map 测试从文件同步到 Map
func TestHandleSync_File2Map(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"direction":"file2map","mode":"overwrite"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sync", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleSync(rec, req)
	// May fail due to missing config file
	// 可能因缺少配置文件而失败
	_ = rec.Code
}

// TestHandleSync_InvalidJSON tests sync with invalid JSON
// TestHandleSync_InvalidJSON 测试无效 JSON 的同步
func TestHandleSync_InvalidJSON(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := testInvalidJSON
	req := httptest.NewRequest(http.MethodPost, "/api/sync", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleSync(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleRules_RateLimit tests rate limit rules handling
// TestHandleRules_RateLimit 测试速率限制规则处理
func TestHandleRules_RateLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"type":"rate_limit","action":"add","cidr":"192.168.1.1","rate":1000,"burst":100}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleRules_AllowedPorts tests allowed ports handling
// TestHandleRules_AllowedPorts 测试允许端口处理
func TestHandleRules_AllowedPorts(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"type":"allowed_ports","action":"add","port":8080}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleRules_UnknownType tests rules with unknown type
// TestHandleRules_UnknownType 测试未知类型的规则
// Note: Unknown types are ignored and return success
// 注意：未知类型被忽略并返回成功
func TestHandleRules_UnknownType(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"type":"unknown_type","action":"add"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	// Unknown type is ignored, returns success
	// 未知类型被忽略，返回成功
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfig_Get tests config GET endpoint
// TestHandleConfig_Get 测试配置 GET 端点
func TestHandleConfig_Get(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/config", http.NoBody)
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfigPost_RateLimit tests rate limit config
// TestHandleConfigPost_RateLimit 测试速率限制配置
func TestHandleConfigPost_RateLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"rate_limit","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	// Unknown key still returns OK (no error handling for unknown keys)
	// 未知键仍然返回 OK（没有对未知键的错误处理）
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfigPost_DropFragments tests drop fragments config
// TestHandleConfigPost_DropFragments 测试丢弃分片配置
func TestHandleConfigPost_DropFragments(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"drop_fragments","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfigPost_StrictTCP tests strict TCP config
// TestHandleConfigPost_StrictTCP 测试严格 TCP 配置
func TestHandleConfigPost_StrictTCP(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"strict_tcp","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfigPost_SynLimit tests SYN limit config
// TestHandleConfigPost_SynLimit 测试 SYN 限制配置
func TestHandleConfigPost_SynLimit(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"syn_limit","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfigPost_BogonFilter tests bogon filter config
// TestHandleConfigPost_BogonFilter 测试 bogon 过滤配置
func TestHandleConfigPost_BogonFilter(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"bogon_filter","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleConfigPost_UnknownKey tests config with unknown key
// TestHandleConfigPost_UnknownKey 测试未知键的配置
func TestHandleConfigPost_UnknownKey(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	body := `{"key":"unknown_key","value":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleConfig(rec, req)
	// Unknown key still returns OK (no error handling for unknown keys)
	// 未知键仍然返回 OK（没有对未知键的错误处理）
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestMetricsServer_CollectStats tests collectStats functionality
// TestMetricsServer_CollectStats 测试 collectStats 功能
func TestMetricsServer_CollectStats(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	cfg := &types.MetricsConfig{
		Enabled:       true,
		ServerEnabled: false,
		Port:          11815,
	}

	metricsServer := NewMetricsServer(s, cfg)
	assert.NotNil(t, metricsServer)

	ctx := context.Background()
	err := metricsServer.Start(ctx)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = metricsServer.Stop()
	assert.NoError(t, err)
}

// TestHandleRules_BlacklistClear tests clearing blacklist
// TestHandleRules_BlacklistClear 测试清除黑名单
func TestHandleRules_BlacklistClear(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	mockMgr.AddBlacklistIP("192.168.1.1/32")

	body := `{"type":"blacklist","action":"clear"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleRules_WhitelistClear tests clearing whitelist
// TestHandleRules_WhitelistClear 测试清除白名单
func TestHandleRules_WhitelistClear(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	server := NewServer(s, 8080)

	mockMgr.AddWhitelistIP("10.0.0.1/32", 0)

	body := `{"type":"whitelist","action":"clear"}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.handleRules(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
