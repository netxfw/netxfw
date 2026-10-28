// Package deploy verifies the authenticity of the netxfw deployment script
// before it is executed with root privileges.
// deploy 包在执行 root 权限部署脚本前验证其真实性。
package deploy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Trust anchor: ed25519 public key embedded in the binary. The private half
// lives only in the maintainer's environment (GitHub secret DEPLOY_SCRIPT_PRIVATE_KEY)
// and signs scripts/deploy.sh on every release; a compromised repository or
// branch cannot forge a valid signature without this key.
// 信任锚点：编译进二进制的 ed25519 公钥。私钥仅存在于发布者环境
// （GitHub secret DEPLOY_SCRIPT_PRIVATE_KEY），每次发布时对 scripts/deploy.sh 签名；
// 仓库或分支被劫持也无法在没有该密钥的情况下伪造合法签名。
const PublicKeyHex = "8e8b61f095a48febf344bffaf9d09c7c5d27c14ee6a4a861d1d0e912e3840d95"

// MaxScriptSize caps downloaded artifacts to prevent memory exhaustion.
// MaxScriptSize 限制下载产物大小，防止内存耗尽。
const MaxScriptSize = 1 << 20 // 1 MiB

// ErrKeyNotConfigured is returned when the embedded public key has not been
// replaced yet, so signature verification cannot be performed.
// ErrKeyNotConfigured 在内置公钥尚未替换、无法执行签名校验时返回。
var ErrKeyNotConfigured = errors.New("deploy: signing public key not configured (set deploy.PublicKeyHex)")

// Verify reports whether sig is a valid ed25519 signature over script made
// with the embedded public key.
// Verify 判断 sig 是否为使用内置公钥对 script 生成的合法 ed25519 签名。
func Verify(script, sig []byte) error {
	return VerifyWithKey(PublicKeyHex, script, sig)
}

// VerifyWithKey checks an ed25519 signature against the given hex public key.
// VerifyWithKey 使用指定的十六进制公钥校验 ed25519 签名。
func VerifyWithKey(pubKeyHex string, script, sig []byte) error {
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrKeyNotConfigured
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), script, sig) {
		return errors.New("deploy: signature verification failed; refusing to execute script")
	}
	return nil
}

// Download fetches url with a hard size cap and timeout.
// Download 下载 url，强制大小上限与超时。
func Download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url) // #nosec G107 // url is built from hardcoded GitHub raw host and validated refs
	if err != nil {
		return nil, fmt.Errorf("deploy: download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deploy: download failed: HTTP %d for %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxScriptSize+1))
	if err != nil {
		return nil, fmt.Errorf("deploy: read failed: %w", err)
	}
	if len(data) > MaxScriptSize {
		return nil, fmt.Errorf("deploy: artifact exceeds %d bytes cap", MaxScriptSize)
	}
	return data, nil
}
