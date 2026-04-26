// Package api provides api functionality.
package api

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
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

func (s *Server) authConfig() (*domainconfig.Config, error) {
	cfg := s.getConfigSnapshot()
	if cfg == nil {
		return nil, errors.New("config snapshot unavailable")
	}
	return cfg, nil
}

func cleanupLoginAttemptsLocked(now time.Time) {
	for key, attempt := range loginAttempts {
		if now.Sub(attempt.LastAttempt) > lockoutTime && !now.Before(attempt.LockedUntil) {
			delete(loginAttempts, key)
		}
	}
}

func isTrustedProxy(remoteIP string, cfg *domainconfig.Config) bool {
	if cfg == nil {
		return false
	}
	if len(cfg.Cloud.ProxyProtocol.TrustedLBRanges) == 0 {
		return false
	}

	addr, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return false
	}

	for _, cidr := range cfg.Cloud.ProxyProtocol.TrustedLBRanges {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func clientIPForLogin(r *http.Request, cfg *domainconfig.Config) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if !isTrustedProxy(host, cfg) {
		return host
	}

	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}

	parts := strings.Split(forwarded, ",")
	candidate := strings.TrimSpace(parts[0])
	if candidate == "" {
		return host
	}
	if _, err := netip.ParseAddr(candidate); err != nil {
		return host
	}
	return candidate
}

// checkLoginRateLimit 检查登录速率限制
func checkLoginRateLimit(ip string) error {
	loginMu.Lock()
	defer loginMu.Unlock()

	now := time.Now()
	cleanupLoginAttemptsLocked(now)

	attempt, exists := loginAttempts[ip]
	if !exists {
		loginAttempts[ip] = &LoginAttempt{
			Count:       1,
			LastAttempt: now,
		}
		return nil
	}

	// 检查是否已锁定
	if now.Before(attempt.LockedUntil) {
		return fmt.Errorf("too many attempts, try again after %v", time.Until(attempt.LockedUntil))
	}

	// 重置过期记录
	if now.Sub(attempt.LastAttempt) > lockoutTime {
		attempt.Count = 0
	}

	attempt.Count++
	attempt.LastAttempt = now

	if attempt.Count > maxAttempts {
		attempt.LockedUntil = now.Add(lockoutTime)
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

// withAuth is a middleware for Bearer JWT authentication.
// withAuth 是用于 Bearer JWT 认证的中间件。
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.authConfig()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if token != "" {
				_, err := verifyToken(token, cfg.Web.Token)
				if err == nil {
					next.ServeHTTP(w, r)
					return
				}
			}
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
	cfg, err := s.authConfig()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	ip := clientIPForLogin(r, cfg)

	// 检查速率限制
	rateLimitErr := checkLoginRateLimit(ip)
	if rateLimitErr != nil {
		http.Error(w, rateLimitErr.Error(), http.StatusTooManyRequests)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	decodeErr := json.NewDecoder(r.Body).Decode(&req)
	if decodeErr != nil {
		http.Error(w, "Invalid Request", http.StatusBadRequest)
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
