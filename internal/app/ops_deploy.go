package app

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/netxfw/netxfw/internal/app/deploy"
	"github.com/netxfw/netxfw/internal/version"
)

// deployScriptRepo is the GitHub repository hosting the signed deployment script.
const deployScriptRepo = "netxfw/netxfw"

// refForVersion maps an application version to the git ref whose scripts/deploy.sh
// must be executed. Updating pins the audited script content of a release;
// "main" is only used by development builds.
// refForVersion 将应用版本映射到部署脚本对应的 git ref。
// 升级时固定使用发布版本的已审计脚本内容；仅开发构建使用 "main"。
func refForVersion(v string) string {
	if v == "" || v == "dev" {
		return "main"
	}
	return v
}

// rawURL builds an https URL on the hardcoded GitHub raw host for the given ref.
func rawURL(ref, file string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/scripts/%s", deployScriptRepo, ref, file)
}

// RunDeployUpdate downloads the deployment script together with its ed25519
// detached signature, verifies the signature against the public key embedded
// in this binary, and only then executes the script. A compromised repository
// or branch cannot forge a valid signature, so curl|bash from a mutable ref
// is no longer an unauthenticated root code-execution path.
// RunDeployUpdate 下载部署脚本及其 ed25519 分离签名，用编译进本二进制的
// 公钥验证签名后才执行。仓库或分支被劫持也无法伪造合法签名，
// 因此对可变 ref 的 curl|bash 不再是无鉴权的 root 代码执行面。
func RunDeployUpdate() error {
	ref := refForVersion(version.Version)

	script, err := deploy.Download(rawURL(ref, "deploy.sh"))
	if err != nil {
		return err
	}

	sigHex, err := deploy.Download(rawURL(ref, "deploy.sh.sig"))
	if err != nil {
		return fmt.Errorf("deploy script signature (deploy.sh.sig on ref %q) is missing: %w; refusing to run unsigned update", ref, err)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("deploy script signature file is malformed (want hex-encoded ed25519 signature)")
	}

	if err := deploy.Verify(script, sig); err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "netxfw-deploy-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	scriptPath := filepath.Join(dir, "deploy.sh")
	if err := os.WriteFile(scriptPath, script, 0700); err != nil { // #nosec G306 // 0700 in private temp dir, content signature-verified
		return fmt.Errorf("failed to stage verified script: %w", err)
	}

	// #nosec G204 -- script bytes verified against the embedded signing key before execution
	cmd := exec.Command("bash", scriptPath) //nolint:gosec
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
