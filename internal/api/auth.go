package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/plugins/types"
)

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
		core.ConfigMu.RLock()
		cfg, err := types.LoadGlobalConfig(s.configPath)
		core.ConfigMu.RUnlock()
		if err != nil {
			http.Error(w, "Config Error", http.StatusInternalServerError)
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

		if token != "" && token == cfg.Web.Token {
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

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid Request", http.StatusBadRequest)
		return
	}

	core.ConfigMu.RLock()
	cfg, err := types.LoadGlobalConfig(s.configPath)
	core.ConfigMu.RUnlock()
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	if req.Token != cfg.Web.Token {
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
	json.NewEncoder(w).Encode(map[string]string{
		"token": signedToken,
	})
}
