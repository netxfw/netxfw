package daemon

import (
	"context"
	"os"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

/**
 * TestConfiguration validates the syntax and values of configuration files.
 * TestConfiguration 验证配置文件的语法和值。
 */
func TestConfiguration(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	log.Infof("🔍 Testing global configuration in %s...", configPath)

	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Error loading config.yaml: %v", err)
	}

	allValid := true
	for _, p := range plugins.GetPlugins() {
		if err := p.Validate(cfg); err != nil {
			log.Errorf("❌ Validation failed for plugin %s: %v", p.Name(), err)
			allValid = false
			continue
		}
		log.Infof("✅ Plugin %s configuration is valid", p.Name())
	}

	if allValid {
		log.Infof("🎉 All configurations are valid!")
	} else {
		os.Exit(1)
	}
}
