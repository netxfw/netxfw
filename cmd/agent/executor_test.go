package agent

import (
	"bytes"
	"testing"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestExecutorXDPCheck(t *testing.T) {
	originalMode := runtime.Mode
	defer func() {
		runtime.Mode = originalMode
	}()

	runtime.Mode = "prod"

	attachedIfaces, _ := xdp.GetAttachedInterfaces(config.GetPinPath())
	if len(attachedIfaces) > 0 {
		t.Skip("Skipping: XDP is already attached, test requires no XDP attachment")
	}

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	executor := NewCommandExecutor(cmd)

	executed := false
	execFunc := func(s *sdk.SDK) error {
		executed = true
		return nil
	}

	executor.ExecuteWithSDK(execFunc)

	output := buf.String()
	assert.False(t, executed, "Business logic should not be executed when XDP is not attached")
	assert.Contains(t, output, "XDP is not attached to any interface", "Should print warning about XDP not attached")
}

func TestExecutorXDPCheckWithManager(t *testing.T) {
	originalMode := runtime.Mode
	defer func() {
		runtime.Mode = originalMode
	}()

	runtime.Mode = "prod"

	attachedIfaces, _ := xdp.GetAttachedInterfaces(config.GetPinPath())
	if len(attachedIfaces) > 0 {
		t.Skip("Skipping: XDP is already attached, test requires no XDP attachment")
	}

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	executor := NewCommandExecutor(cmd)

	executed := false
	execFunc := func(mgr *xdp.Manager) error {
		executed = true
		return nil
	}

	executor.ExecuteWithManager(execFunc)

	output := buf.String()
	assert.False(t, executed, "Business logic should not be executed when XDP is not attached")
	assert.Contains(t, output, "XDP is not attached to any interface", "Should print warning about XDP not attached")
}
