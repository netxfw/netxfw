// Package api provides api functionality.
package api

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
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

const (
	tokenVersion = 1
	tokenIssuer  = "netxfw"
)

var tokenClockSkew = 30 * time.Second

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
		return fmt.Errorf("too many attempts, try again after %v", time.Until(attempt.LockedUntil))
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

// TokenClaims represents the payload of the session JWT.
// TokenClaims 代表会话 JWT 的负载。
type TokenClaims struct {
	Role    string `json:"role"`
	Version int    `json:"ver"`
	jwt.RegisteredClaims
}

// signToken creates a signed HS256 JWT.
// signToken 创建一个已签名的 HS256 JWT。
func signToken(claims TokenClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = "JWT"
	return token.SignedString([]byte(secret))
}

// verifyToken checks the signature, claims and expiration of the token.
// verifyToken 检查令牌的签名、声明和过期时间。
func verifyToken(tokenString string, secret string) (*TokenClaims, error) {
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method == nil {
			return nil, errors.New("missing signing method")
		}
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return []byte(secret), nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithLeeway(tokenClockSkew),
	)
	if err != nil {
		return nil, normalizeJWTError(err)
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.Version != tokenVersion {
		return nil, fmt.Errorf("unsupported token version: %d", claims.Version)
	}
	if claims.Role == "" {
		return nil, errors.New("missing role claim")
	}
	return claims, nil
}

func normalizeJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return errors.New("invalid token format")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return errors.New("invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired):
		return errors.New("token expired")
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return errors.New("token not valid yet")
	default:
		return err
	}
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
	now := time.Now()
	claims := TokenClaims{
		Role:    "admin",
		Version: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
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
