//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/livp123/netxfw/internal/config"
)

/**
 * Attach mounts the XDP program to the specified network interfaces.
 * It tries Offload mode, then Native mode, and finally Generic mode as fallbacks.
 * The XDP program is attached using link.XDP_FLAGS_REPLACE or similar to ensure it stays in kernel.
 * Attach 将 XDP 程序挂载到指定的网络接口。
 * 它尝试 Offload 模式，然后是 Native 模式，最后是 Generic 模式作为备选方案。
 * XDP 程序使用 link.XDP_FLAGS_REPLACE 或类似方式挂载，以确保其留在内核中。
 */
func (m *Manager) Attach(interfaces []string) error {
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			m.logger.Warnf("Skip interface %s: %v", name, err)
			continue
		}

		// Try to atomic update existing XDP link / 尝试原子更新现有的 XDP 链接
		linkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("link_%s", name))
		var attached bool

		if l, err := link.LoadPinnedLink(linkPath, nil); err == nil {
			if err := l.Update(m.objs.XdpFirewall); err == nil {
				m.logger.Infof("✅ Atomic Reload: Updated XDP program on %s", name)
				l.Close()
				attached = true
			} else {
				m.logger.Warnf("⚠️  Atomic Reload failed on %s: %v. Fallback to detach/attach.", name, err)
				l.Close()
				_ = os.Remove(linkPath) // Force remove to allow re-attach / 强制删除以允许重新挂载
			}
		}

		if !attached {
			modes := []struct {
				name string
				flag link.XDPAttachFlags
			}{
				{"Offload", link.XDPOffloadMode},
				{"Native", link.XDPDriverMode},
				{"Generic", link.XDPGenericMode},
			}

			for _, mode := range modes {
				l, err := link.AttachXDP(link.XDPOptions{
					Program:   m.objs.XdpFirewall,
					Interface: iface.Index,
					Flags:     mode.flag,
				})

				if err == nil {
					// Pin the link to filesystem to make it persistent after process exit
					// 将链接固定到文件系统，使其在进程退出后保持持久
					_ = os.Remove(linkPath) // Remove old link pin if exists / 如果存在旧的链接固定点，则将其删除
					if pinErr := l.Pin(linkPath); pinErr != nil {
						m.logger.Warnf("⚠️  Failed to pin link on %s: %v", name, pinErr)
						l.Close()
						continue
					}
					m.logger.Infof("✅ Attached XDP on %s (Mode: %s) and pinned link", name, mode.name)
					attached = true
					break
				}
				m.logger.Warnf("⚠️  Failed to attach XDP on %s using %s mode: %v", name, mode.name, err)
			}
		}

		// Attach TC for egress tracking (required for Conntrack) / 附加 TC 用于出口追踪（连接跟踪 Conntrack 所需）
		// 1. Ensure clsact qdisc exists / 确保 clsact qdisc 存在
		_ = exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run()

		// 2. Attach TC program / 挂载 TC 程序
		tcLinkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("tc_link_%s", name))
		var tcAttached bool

		// Try atomic update for TC / 尝试原子更新 TC
		if tl, err := link.LoadPinnedLink(tcLinkPath, nil); err == nil {
			if err := tl.Update(m.objs.TcEgress); err == nil {
				m.logger.Infof("✅ Atomic Reload: Updated TC Egress on %s", name)
				tl.Close()
				tcAttached = true
			} else {
				tl.Close()
				_ = os.Remove(tcLinkPath)
			}
		}

		if !tcAttached {
			tcLink, attachErr := link.AttachTCX(link.TCXOptions{
				Program:   m.objs.TcEgress,
				Interface: iface.Index,
				Attach:    ebpf.AttachTCXEgress,
			})
			if attachErr == nil {
				_ = os.Remove(tcLinkPath)
				if pinErr := tcLink.Pin(tcLinkPath); pinErr != nil {
					m.logger.Warnf("⚠️  Failed to pin TC link on %s: %v", name, pinErr)
					tcLink.Close()
				} else {
					m.logger.Infof("✅ Attached TC Egress on %s and pinned link", name)
				}
			} else {
				m.logger.Warnf("⚠️  Failed to attach TC Egress on %s: %v (Conntrack will not work for this interface)", name, attachErr)
			}
		}

		if !attached {
			m.logger.Errorf("❌ Failed to attach XDP on %s with any mode", name)
		}
	}
	return nil
}

/**
 * Detach removes the XDP program from the specified network interfaces by unpinning and closing links.
 * Detach 通过取消固定和关闭链接，从指定的网络接口移除 XDP 程序。
 */
func (m *Manager) Detach(interfaces []string) error {
	for _, name := range interfaces {
		linkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("link_%s", name))
		l, err := link.LoadPinnedLink(linkPath, nil)
		if err != nil {
			m.logger.Warnf("⚠️  No pinned link found for %s, trying manual detach...", name)
			continue
		}
		if err := l.Close(); err != nil {
			m.logger.Errorf("❌ Failed to close link for %s: %v", name, err)
		} else {
			_ = os.Remove(linkPath)
			m.logger.Infof("✅ Detached XDP from %s", name)
		}

		// Detach TC link / 分离 TC 链接
		tcLinkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("tc_link_%s", name))
		if tl, err := link.LoadPinnedLink(tcLinkPath, nil); err == nil {
			if err := tl.Close(); err != nil {
				m.logger.Errorf("❌ Failed to close TC link for %s: %v", name, err)
			} else {
				_ = os.Remove(tcLinkPath)
				m.logger.Infof("✅ Detached TC Egress from %s", name)
			}
		}
	}
	return nil
}

/**
 * GetAttachedInterfaces returns a list of interfaces that currently have XDP/TC programs attached
 * by looking for pinned links in the default pin path.
 * GetAttachedInterfaces 通过在默认固定路径中查找固定链接，返回当前挂载了 XDP/TC 程序的接口列表。
 */
func GetAttachedInterfaces(pinPath string) ([]string, error) {
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var interfaces []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "link_") {
			iface := strings.TrimPrefix(entry.Name(), "link_")
			interfaces = append(interfaces, iface)
		}
	}
	return interfaces, nil
}

// InterfaceXDPInfo contains XDP attachment information for an interface
// InterfaceXDPInfo 包含接口的 XDP 挂载信息
type InterfaceXDPInfo struct {
	Name      string    // Interface name / 接口名称
	ProgramID uint32    // XDP program ID / XDP 程序 ID
	LinkID    uint32    // Link ID / 链接 ID
	Mode      string    // Attachment mode / 挂载模式
	LoadTime  time.Time // Program load time / 程序加载时间
}

/**
 * GetAttachedInterfacesWithInfo returns detailed XDP attachment information for all attached interfaces.
 * GetAttachedInterfacesWithInfo 返回所有已挂载接口的详细 XDP 挂载信息。
 */
func GetAttachedInterfacesWithInfo(pinPath string) ([]InterfaceXDPInfo, error) {
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	interfaces := make([]InterfaceXDPInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "link_") {
			continue
		}
		ifaceName := strings.TrimPrefix(entry.Name(), "link_")
		linkPath := filepath.Join(pinPath, entry.Name())

		// Load the pinned link to get info / 加载固定的链接以获取信息
		l, err := link.LoadPinnedLink(linkPath, nil)
		if err != nil {
			// If we can't load the link, still add the interface with 0 ID
			// 如果无法加载链接，仍然添加接口但 ID 为 0
			interfaces = append(interfaces, InterfaceXDPInfo{
				Name:      ifaceName,
				ProgramID: 0,
				LinkID:    0,
				Mode:      "Native",
			})
			continue
		}

		// Get link info / 获取链接信息
		info, err := l.Info()
		if err != nil {
			l.Close()
			interfaces = append(interfaces, InterfaceXDPInfo{
				Name:      ifaceName,
				ProgramID: 0,
				LinkID:    0,
				Mode:      "Native",
			})
			continue
		}

		// Determine mode from XDP info / 从 XDP 信息确定模式
		mode := "Native"
		if xdpInfo := info.XDP(); xdpInfo != nil {
			// Check ifindex to determine mode / 检查 ifindex 以确定模式
			// We can't directly get the mode, so we default to Native
			// 我们无法直接获取模式，所以默认为 Native
			_ = xdpInfo.Ifindex
		}

		// Get program load time / 获取程序加载时间
		var loadTime time.Time
		progID := info.Program
		if progID > 0 {
			// Try to get program info for load time / 尝试获取程序信息以获取加载时间
			if prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID)); err == nil {
				if progInfo, err := prog.Info(); err == nil {
					if loadDuration, ok := progInfo.LoadTime(); ok {
						// LoadTime is duration since boot, convert to absolute time
						// LoadTime 是从启动开始的持续时间，转换为绝对时间
						loadTime = time.Now().Add(-loadDuration)
					}
				}
				prog.Close()
			}
		}

		interfaces = append(interfaces, InterfaceXDPInfo{
			Name:      ifaceName,
			ProgramID: uint32(info.Program),
			LinkID:    uint32(info.ID),
			Mode:      mode,
			LoadTime:  loadTime,
		})
		l.Close()
	}
	return interfaces, nil
}

/**
 * ForceCleanup removes all pinned maps at the specified path.
 * ForceCleanup 删除指定路径下的所有固定 Map。
 */
func ForceCleanup(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(path)
}

/**
 * Pin saves maps to the filesystem for persistence and external access.
 * Pin 将 Map 保存到文件系统以进行持久化和外部访问。
 */
func (m *Manager) Pin(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}

	pinMap := func(ebpfMap *ebpf.Map, name string) {
		if ebpfMap == nil {
			return
		}
		p := path + "/" + name
		_ = os.Remove(p) // Ensure old pin is removed / 确保旧的固定点被移除
		if err := ebpfMap.Pin(p); err != nil {
			m.logger.Warnf("⚠️  Failed to pin %s: %v", name, err)
		}
	}

	// Pin core maps using new unified names
	// 使用新的统一名称固定核心 Map
	pinMap(m.conntrackMap, "conntrack_map")
	pinMap(m.staticBlacklist, "static_blacklist")
	pinMap(m.dynamicBlacklist, "dynamic_blacklist")
	pinMap(m.criticalBlacklist, "critical_blacklist")
	pinMap(m.whitelist, "whitelist")
	pinMap(m.ruleMap, "rule_map")
	pinMap(m.topDropMap, "top_drop_map")
	pinMap(m.topPassMap, "top_pass_map")
	pinMap(m.statsGlobalMap, "stats_global_map")
	pinMap(m.ratelimitMap, "ratelimit_map")
	pinMap(m.globalConfig, "global_config")
	pinMap(m.jmpTable, "jmp_table")
	pinMap(m.xskMap, "xsk_map")

	return nil
}

// Unpin removes maps from the filesystem.
// Unpin 从文件系统中移除 Map。
func (m *Manager) Unpin(path string) error {
	// Unpin core maps / 取消固定核心 Map
	unpinMap := func(ebpfMap *ebpf.Map) {
		if ebpfMap != nil {
			_ = ebpfMap.Unpin()
		}
	}

	unpinMap(m.conntrackMap)
	unpinMap(m.staticBlacklist)
	unpinMap(m.dynamicBlacklist)
	unpinMap(m.criticalBlacklist)
	unpinMap(m.whitelist)
	unpinMap(m.ruleMap)
	unpinMap(m.topDropMap)
	unpinMap(m.topPassMap)
	unpinMap(m.statsGlobalMap)
	unpinMap(m.ratelimitMap)
	unpinMap(m.globalConfig)
	unpinMap(m.jmpTable)
	unpinMap(m.xskMap)

	return os.RemoveAll(path)
}
