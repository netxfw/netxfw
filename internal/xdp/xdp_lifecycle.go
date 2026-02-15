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
				// Using Pin-less link or simply not storing the link object if we want it to persist.
				// However, in cilium/ebpf, if the link object is closed, the program is detached.
				// To keep it persistent, we need to PIN the link or use Raw attach.
				// 使用不带固定点的链接，或者如果我们希望它持久化，则根本不存储链接对象。
				// 然而，在 cilium/ebpf 中，如果链接对象被关闭，程序将被卸载。
				// 为了保持持久性，我们需要固定（PIN）链接或使用原始挂载。
				l, err := link.AttachXDP(link.XDPOptions{
					Program:   m.objs.XdpFirewall,
					Interface: iface.Index,
					Flags:     mode.flag,
				})

				if err == nil {
					// Pin the link to filesystem to make it persistent after process exit
					// 将链接固定到文件系统，使其在进程退出后保持持久
					_ = os.Remove(linkPath) // Remove old link pin if exists / 如果存在旧的链接固定点，则将其删除
					if err := l.Pin(linkPath); err != nil {
						m.logger.Warnf("⚠️  Failed to pin link on %s: %v", name, err)
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
			tcLink, err := link.AttachTCX(link.TCXOptions{
				Program:   m.objs.TcEgress,
				Interface: iface.Index,
				Attach:    ebpf.AttachTCXEgress,
			})
			if err == nil {
				_ = os.Remove(tcLinkPath)
				if err := tcLink.Pin(tcLinkPath); err != nil {
					m.logger.Warnf("⚠️  Failed to pin TC link on %s: %v", name, err)
					tcLink.Close()
				} else {
					m.logger.Infof("✅ Attached TC Egress on %s and pinned link", name)
				}
			} else {
				m.logger.Warnf("⚠️  Failed to attach TC Egress on %s: %v (Conntrack will not work for this interface)", name, err)
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
			// Fallback: try to detach using interface index if possible,
			// but usually unpinning the persistent link is enough.
			// 备选方案：如果可能，尝试使用接口索引进行分离，但通常取消固定持久链接就足够了。
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

	pinMap(m.lockList, config.MapLockList)
	pinMap(m.dynLockList, config.MapDynLockList)
	pinMap(m.whitelist, config.MapWhitelist)
	pinMap(m.allowedPorts, config.MapAllowedPorts)
	pinMap(m.ipPortRules, config.MapIPPortRules)
	pinMap(m.globalConfig, config.MapGlobalConfig)
	pinMap(m.dropStats, config.MapDropStats)
	pinMap(m.dropReasonStats, config.MapDropReasonStats)
	pinMap(m.icmpLimitMap, config.MapICMPLimit)
	pinMap(m.conntrackMap, config.MapConntrack)
	pinMap(m.passStats, config.MapPassStats)
	pinMap(m.passReasonStats, config.MapPassReasonStats)
	pinMap(m.ratelimitConfig, config.MapRatelimitConfig)
	pinMap(m.ratelimitState, config.MapRatelimitState)

	return nil
}

// Unpin removes maps from the filesystem.
// Unpin 从文件系统中移除 Map。
func (m *Manager) Unpin(path string) error {
	_ = m.lockList.Unpin()
	if m.dynLockList != nil {
		_ = m.dynLockList.Unpin()
	}
	_ = m.whitelist.Unpin()
	_ = m.allowedPorts.Unpin()
	_ = m.ipPortRules.Unpin()
	_ = m.globalConfig.Unpin()
	_ = m.dropStats.Unpin()
	if m.dropReasonStats != nil {
		_ = m.dropReasonStats.Unpin()
	}
	_ = m.icmpLimitMap.Unpin()
	_ = m.conntrackMap.Unpin()
	if m.passStats != nil {
		_ = m.passStats.Unpin()
	}
	_ = m.ratelimitConfig.Unpin()
	_ = m.ratelimitState.Unpin()
	return os.RemoveAll(path)
}
