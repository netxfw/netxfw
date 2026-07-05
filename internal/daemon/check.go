package daemon

import (
	"context"

	runtimehost "github.com/netxfw/netxfw/internal/adapters/plugins/runtime"
	appconfig "github.com/netxfw/netxfw/internal/app/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

/**
 * TestConfiguration validates the syntax and values of configuration files.
 * TestConfiguration 验证配置文件的语法和值。
 */
func TestConfiguration(ctx context.Context) bool {
	log := logger.Get(ctx)
	configPath := appconfig.GetConfigPath()
	log.Infof("[SCAN] Testing global configuration in %s...", configPath)

	cfg, err := appconfig.LoadConfig()
	if err != nil {
		log.Errorf("[ERROR] Error loading TOML config: %v", err)
		return false
	}

	host := runtimehost.NewHost(nil)
	failures := host.ValidateConfig(cfg)
	failedNames := make(map[string]error, len(failures))
	for _, failure := range failures {
		failedNames[failure.Name] = failure.Err
	}

	allValid := true
	for _, item := range host.Inventory() {
		if err, failed := failedNames[item.Name]; failed {
			log.Errorf("[ERROR] Validation failed for plugin %s: %v", item.Name, err)
			allValid = false
			continue
		}
		log.Infof("[OK] Plugin %s configuration is valid", item.Name)
	}

	if allValid {
		log.Infof("[SUCCESS] All configurations are valid!")
	} else {
		log.Errorf("[ERROR] Configuration validation failed")
	}
	return allValid
}
