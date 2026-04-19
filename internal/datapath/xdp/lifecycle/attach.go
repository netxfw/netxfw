package lifecycle

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// AttachWithMode attaches the XDP program with an explicit mode selection.
func AttachWithMode(ctx context.Context, pinPath string, interfaces []string, mode string, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) ([]string, error) {
	_ = ctx

	manager, err := datapathprograms.CreateManager(globalCfg.Capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %w", err)
	}
	defer manager.Close()

	if err := manager.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("failed to pin maps: %w", err)
	}

	var attachMode link.XDPAttachFlags
	var attachModeName string
	switch mode {
	case "offload":
		attachMode = link.XDPOffloadMode
		attachModeName = "Offload"
	case "drv":
		attachMode = link.XDPDriverMode
		attachModeName = "Native"
	case "skb":
		attachMode = link.XDPGenericMode
		attachModeName = "Generic"
	default:
		return nil, fmt.Errorf("invalid mode: %s", mode)
	}

	attached := make([]string, 0, len(interfaces))
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Warnf("[WARN]  Skip interface %s: %v", name, err)
			continue
		}

		log.Infof("[INFO]  Attempting to attach XDP on %s with mode: %s", name, attachModeName)
		l, err := datapathprograms.AttachProgram(manager.XDPProgram(), iface.Index, attachMode)
		if err != nil {
			log.Warnf("[WARN]  Failed to attach XDP on %s using %s mode: %v", name, attachModeName, err)
			continue
		}

		linkPath := filepath.Join(pinPath, fmt.Sprintf("link_%s", name))
		_ = os.Remove(linkPath)
		if pinErr := l.Pin(linkPath); pinErr != nil {
			log.Warnf("[WARN]  Failed to pin link on %s: %v", name, pinErr)
			l.Close()
			continue
		}
		log.Infof("[OK] Attached XDP on %s (Mode: %s) and pinned link", name, attachModeName)
		attached = append(attached, name)
	}

	if len(attached) == 0 {
		return nil, fmt.Errorf("failed to attach XDP on any interface")
	}

	return attached, nil
}
