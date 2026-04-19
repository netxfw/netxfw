package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

// 配置缓存 - 避免每次请求都重新加载配置文件
var (
	configCache *domainconfig.Config
	configMu    sync.RWMutex
	lastLoad    time.Time
	cacheTTL    = 5 * time.Second
)

// 登录速率限制
var (
	loginAttempts = make(map[string]*LoginAttempt)
	loginMu       sync.Mutex
	maxAttempts   = 5
	lockoutTime   = 15 * time.Minute
)

// LoginAttempt 记录登录尝试
type LoginAttempt struct {
	Count       int
	LastAttempt time.Time
	LockedUntil time.Time
}

// getCachedConfig 获取缓存的配置
func getCachedConfig() (*domainconfig.Config, error) {
	configMu.RLock()
	if configCache != nil && time.Since(lastLoad) < cacheTTL {
		configMu.RUnlock()
		return configCache, nil
	}
	configMu.RUnlock()

	configMu.Lock()
	defer configMu.Unlock()

	// 双重检查
	if configCache != nil && time.Since(lastLoad) < cacheTTL {
		return configCache, nil
	}

	cfg, err := appconfig.LoadConfig()
	if err != nil {
		return nil, err
	}
	configCache = cfg
	lastLoad = time.Now()
	return cfg, nil
}

// checkLoginRateLimit 检查登录速率限制
func checkLoginRateLimit(ip string) error {
	loginMu.Lock()
	defer loginMu.Unlock()

	attempt, exists := loginAttempts[ip]
	if !exists {
		loginAttempts[ip] = &LoginAttempt{
			Count:       1,
			LastAttempt: time.Now(),
		}
		return nil
	}

	// 检查是否已锁定
	if time.Now().Before(attempt.LockedUntil) {
		return fmt.Errorf("too many attempts, try again after %v", attempt.LockedUntil.Sub(time.Now()))
	}

	// 重置过期记录
	if time.Since(attempt.LastAttempt) > lockoutTime {
		attempt.Count = 0
	}

	attempt.Count++
	attempt.LastAttempt = time.Now()

	if attempt.Count > maxAttempts {
		attempt.LockedUntil = time.Now().Add(lockoutTime)
		return fmt.Errorf("too many attempts, locked for %v", lockoutTime)
	}

	return nil
}

// TokenClaims represents the payload of the JWT-like token
// TokenClaims 代表类似 JWT 的令牌负载
type TokenClaims struct {
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
}

// signToken creates a signed token string
// signToken 创建一个已签名的令牌字符串
func signToken(claims TokenClaims, secret string) (string, error) {
	header := `{"alg":"HS256","typ":"JWT"}`
	headerEnc := base64.RawURLEncoding.EncodeToString([]byte(header))

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadBytes)

	unsigned := headerEnc + "." + payloadEnc

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsigned))
	sig := h.Sum(nil)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return unsigned + "." + sigEnc, nil
}

// verifyToken checks the signature and expiration of the token
// verifyToken 检查令牌的签名和过期时间
func verifyToken(tokenString string, secret string) (*TokenClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsigned := parts[0] + "." + parts[1]
	sigEnc := parts[2]

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsigned))
	expectedSig := h.Sum(nil)
	expectedSigEnc := base64.RawURLEncoding.EncodeToString(expectedSig)

	if !hmac.Equal([]byte(sigEnc), []byte(expectedSigEnc)) {
		return nil, errors.New("invalid signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}

	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// withAuth is a middleware for token-based authentication (Supports Bearer Token & Legacy Query Param)
// withAuth 是用于基于令牌认证的中间件（支持 Bearer Token 和旧查询参数）
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := getCachedConfig()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if cfg == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// 1. Check Authorization Header (Bearer <Token>)
		// 1. 检查授权头（Bearer <Token>）
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			_, err := verifyToken(token, cfg.Web.Token)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 2. Check Legacy Query Param / Header (Backwards Compatibility)
		// 2. 检查旧查询参数/头部（向后兼容性）
		token := r.Header.Get("X-NetXFW-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// 使用常量时间比较防止时序攻击
		if token != "" && hmac.Equal([]byte(token), []byte(cfg.Web.Token)) {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// handleLogin exchanges the master token/password for a session JWT
// handleLogin 将主令牌/密码交换为会话 JWT
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取客户端 IP 用于速率限制
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}

	// 检查速率限制
	if err := checkLoginRateLimit(ip); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid Request", http.StatusBadRequest)
		return
	}

	cfg, err := getCachedConfig()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 使用常量时间比较
	if !hmac.Equal([]byte(req.Token), []byte(cfg.Web.Token)) {
		http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	claims := TokenClaims{
		Role: "admin",
		Exp:  time.Now().Add(24 * time.Hour).Unix(), // 24 hour session
		Iat:  time.Now().Unix(),
	}

	signedToken, err := signToken(claims, cfg.Web.Token)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"token": signedToken,
	}); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
