package agent

import (
	"bytes"
	"strings"
	"testing"

	"github.com/netxfw/netxfw/cmd/common"
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

func TestConsumeLastCommandErrorClearsState(t *testing.T) {
	want := "boom"
	setLastCommandError(assertiveError(want))

	err := ConsumeLastCommandError()
	if err == nil || err.Error() != want {
		t.Fatalf("expected %q, got %v", want, err)
	}

	if err := ConsumeLastCommandError(); err != nil {
		t.Fatalf("expected cleared command error state, got %v", err)
	}
}

func TestExecuteWithSDKReportsInitializationFailure(t *testing.T) {
	originalMode := app.GetRuntimeMode()
	originalMock := common.MockSDK
	defer func() {
		app.SetRuntimeMode(originalMode)
		common.SetMockSDK(originalMock)
		ConsumeLastCommandError()
	}()

	app.SetRuntimeMode("test")
	common.SetMockSDK(nil)

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	executed := false
	NewCommandExecutor(cmd).ExecuteWithSDK(func(_ *sdk.SDK) error {
		executed = true
		return nil
	})

	if executed {
		t.Fatalf("expected business callback to be skipped when SDK init fails")
	}

	err := ConsumeLastCommandError()
	if err == nil {
		t.Fatalf("expected command error to be recorded")
	}
	if !strings.Contains(err.Error(), "Failed to get SDK") {
		t.Fatalf("expected SDK init failure to be wrapped, got %v", err)
	}
}

type assertiveError string

func (e assertiveError) Error() string {
	return string(e)
}
