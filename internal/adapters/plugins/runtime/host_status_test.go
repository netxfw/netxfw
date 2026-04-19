package runtime

import (
	"testing"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/internal/ports"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

type statusTestRegistry struct {
	plugins []RegisteredPlugin
}

func (r statusTestRegistry) Plugins() []RegisteredPlugin {
	return r.plugins
}

func (r statusTestRegistry) Inventory() []domainruntime.Descriptor {
	return nil
}

type statusTestPlugin struct {
	name        string
	kind        ports.PluginType
	validateErr error
}

func (p statusTestPlugin) SDKPlugin() sdk.RuntimePlugin               { return nil }
func (p statusTestPlugin) Name() string                               { return p.name }
func (p statusTestPlugin) Init(ctx *sdk.RuntimePluginContext) error   { return nil }
func (p statusTestPlugin) Start(ctx *sdk.RuntimePluginContext) error  { return nil }
func (p statusTestPlugin) Stop() error                                { return nil }
func (p statusTestPlugin) Reload(ctx *sdk.RuntimePluginContext) error { return nil }
func (p statusTestPlugin) DefaultConfig() any                         { return nil }
func (p statusTestPlugin) Validate(config *sdk.GlobalConfig) error    { return p.validateErr }
func (p statusTestPlugin) Type() ports.PluginType                     { return p.kind }

func TestRuntimeHostStatuses(t *testing.T) {
	host := NewHost(statusTestRegistry{
		plugins: []RegisteredPlugin{
			statusTestPlugin{name: "log_engine", kind: ports.PluginTypeExtension},
			statusTestPlugin{name: "metrics", kind: ports.PluginTypeExtension},
			statusTestPlugin{name: "web", kind: ports.PluginTypeExtension},
		},
	})

	cfg := &domainconfig.Config{}
	cfg.LogEngine.Enabled = true
	cfg.Web.Enabled = true

	statuses := host.Statuses(cfg)
	if len(statuses) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(statuses))
	}

	if !statuses[0].Enabled || !statuses[0].Running || !statuses[0].Healthy {
		t.Fatalf("expected log_engine to be enabled and healthy, got %+v", statuses[0])
	}
	if statuses[1].Enabled || statuses[1].Message != "disabled by config" {
		t.Fatalf("expected metrics to be disabled, got %+v", statuses[1])
	}
	if !statuses[2].Enabled || !statuses[2].Running || !statuses[2].Healthy {
		t.Fatalf("expected web to be enabled and healthy, got %+v", statuses[2])
	}
}
