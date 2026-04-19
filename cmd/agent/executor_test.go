package agent

import (
	"bytes"
	"testing"

	"github.com/netxfw/netxfw/internal/app"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestExecutorXDPCheck(t *testing.T) {
	originalMode := app.GetRuntimeMode()
	defer func() {
		app.SetRuntimeMode(originalMode)
	}()

	app.SetRuntimeMode("prod")

	attachedIfaces, _ := app.GetAttachedInterfaceInfos()
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

func TestExecutorXDPCheckWithSDKAndConfig(t *testing.T) {
	originalMode := app.GetRuntimeMode()
	defer func() {
		app.SetRuntimeMode(originalMode)
	}()

	app.SetRuntimeMode("prod")

	attachedIfaces, _ := app.GetAttachedInterfaceInfos()
	if len(attachedIfaces) > 0 {
		t.Skip("Skipping: XDP is already attached, test requires no XDP attachment")
	}

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	executor := NewCommandExecutor(cmd)

	executed := false
	execFunc := func(_ *sdk.GlobalConfig, _ *sdk.SDK) error {
		executed = true
		return nil
	}

	executor.ExecuteWithSDKAndConfig(execFunc)

	output := buf.String()
	assert.False(t, executed, "Business logic should not be executed when XDP is not attached")
	assert.Contains(t, output, "XDP is not attached to any interface", "Should print warning about XDP not attached")
}
