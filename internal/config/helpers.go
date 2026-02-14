package config

import (
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
)

/**
 * LoadMap loads a pinned BPF map by its name.
 * It automatically resolves the pin path.
 * LoadMap 通过名称加载固定的 BPF Map。
 * 它会自动解析固定路径。
 */
func LoadMap(mapName string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(GetPinPath(), mapName), nil)
}

/**
 * ClearMap loads and clears a BPF map by name.
 * ClearMap 通过名称加载并清除 BPF Map。
 */
// func ClearMap(mapName string) error {
// 	m, err := LoadMap(mapName)
// 	if err != nil {
// 		return err
// 	}
// 	defer m.Close()
// 	_, err = xdp.ClearMap(m)
// 	return err
// }

/**
 * GetConfigPath resolves the configuration file path.
 * It prioritizes the CLI flag (runtime.ConfigPath) over the default.
 * GetConfigPath 解析配置文件路径。
 * 优先使用 CLI 标志 (runtime.ConfigPath)，其次是默认值。
 */
func GetConfigPath() string {
	if runtime.ConfigPath != "" {
		return runtime.ConfigPath
	}
	return DefaultConfigPath
}

/**
 * GetPinPath resolves the BPF pin path.
 * It checks the configuration file first, then falls back to the constant default.
 * GetPinPath 解析 BPF 固定路径。
 * 首先检查配置文件，然后回退到常量默认值。
 */
func GetPinPath() string {
	cfgPath := GetConfigPath()
	cfg, err := types.LoadGlobalConfig(cfgPath)
	if err == nil && cfg.Base.BPFPinPath != "" {
		return cfg.Base.BPFPinPath
	}
	return BPFPinPath
}
