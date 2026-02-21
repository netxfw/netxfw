//go:build linux
// +build linux

package xdp

import (
	"fmt"

	"github.com/cilium/ebpf"
)

/**
 * LoadPlugin loads a BPF program from an ELF file and inserts it into the jump table.
 * LoadPlugin 从 ELF 文件加载 BPF 程序并将其插入跳转表。
 */
func (m *Manager) LoadPlugin(elfPath string, index int) error {
	if index < ProgIdxPluginStart || index > ProgIdxPluginEnd {
		return fmt.Errorf("invalid plugin index: %d (must be between %d and %d)",
			index, ProgIdxPluginStart, ProgIdxPluginEnd)
	}

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		return fmt.Errorf("load plugin spec: %w", err)
	}

	// For simplicity, we assume the first XDP program found is the plugin / 为了简单起见，我们假设找到的第一个 XDP 程序就是插件
	var progSpec *ebpf.ProgramSpec
	for _, p := range spec.Programs {
		if p.Type == ebpf.XDP {
			progSpec = p
			break
		}
	}

	if progSpec == nil {
		return fmt.Errorf("no XDP program found in plugin: %s", elfPath)
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return fmt.Errorf("load plugin program: %w", err)
	}
	// Note: We don't close the program here as it needs to stay in the jmpTable
	// 注意：我们在这里不关闭程序，因为它需要留在 jmpTable 中

	if err := m.jmpTable.Update(uint32(index), prog, ebpf.UpdateAny); err != nil {
		prog.Close()
		return fmt.Errorf("failed to update jmp_table with plugin: %w", err)
	}

	m.logger.Infof("✅ Plugin loaded: %s at index %d", elfPath, index)
	return nil
}

/**
 * RemovePlugin removes a plugin from the jump table.
 * RemovePlugin 从跳转表中移除插件。
 */
func (m *Manager) RemovePlugin(index int) error {
	if index < ProgIdxPluginStart || index > ProgIdxPluginEnd {
		return fmt.Errorf("invalid plugin index: %d", index)
	}

	if err := m.jmpTable.Delete(uint32(index)); err != nil {
		return fmt.Errorf("failed to remove plugin from jmp_table: %w", err)
	}

	m.logger.Infof("✅ Plugin removed from index %d", index)
	return nil
}
