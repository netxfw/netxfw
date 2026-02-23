package agent

import (
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestFlagRegistrationConsistency(t *testing.T) {
	commands := []*cobra.Command{
		ruleAddCmd, ruleRemoveCmd, ruleListCmd, ruleImportCmd, ruleExportCmd,
		QuickBlockCmd, QuickUnlockCmd, QuickAllowCmd, QuickUnallowCmd, QuickClearCmd,
		portAddCmd, portRemoveCmd,
		limitAddCmd, limitRemoveCmd, limitListCmd,
		securityFragmentsCmd, securityStrictTCPCmd, securitySYNLimitCmd, securityBogonCmd, securityAutoBlockCmd, securityAutoBlockExpiryCmd,
	}

	for _, cmd := range commands {
		t.Run(cmd.Name(), func(t *testing.T) {
			configFlag := cmd.Flags().Lookup("config")
			assert.NotNil(t, configFlag, "Command %s should have 'config' flag", cmd.Name())
			assert.Equal(t, "c", configFlag.Shorthand)

			interfaceFlag := cmd.Flags().Lookup("interface")
			assert.NotNil(t, interfaceFlag, "Command %s should have 'interface' flag", cmd.Name())
			assert.Equal(t, "i", interfaceFlag.Shorthand)
		})
	}
}

func TestCommandExecutorFlagApplying(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	// Test config flag applying
	config.SetConfigPath("")
	cmd := &cobra.Command{}
	RegisterCommonFlags(cmd)
	cmd.SetArgs([]string{"-c", "/tmp/test_config.yaml"})
	_ = cmd.ParseFlags([]string{"-c", "/tmp/test_config.yaml"})

	ce := &CommandExecutor{}
	ce.applyFlags(cmd)

	assert.Equal(t, "/tmp/test_config.yaml", config.GetConfigPath())
}
