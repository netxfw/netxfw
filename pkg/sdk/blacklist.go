package sdk

import "time"

// BlacklistAPI defines the interface for blacklist operations.
// BlacklistAPI 定义了黑名单操作的接口。
type BlacklistAPI interface {
	// Add adds an IP or CIDR to the blacklist.
	// Add 将 IP 或 CIDR 添加到黑名单。
	Add(cidr string) error

	// AddWithDuration adds an IP or CIDR to the blacklist with an expiration time.
	// AddWithDuration 将 IP 或 CIDR 添加到具有过期时间的黑名单中。
	AddWithDuration(cidr string, duration time.Duration) error

	// AddWithFile adds an IP or CIDR to the blacklist and persists it to a file.
	// AddWithFile 将 IP 或 CIDR 添加到黑名单并持久化到文件。
	AddWithFile(cidr string, file string) error

	// Remove removes an IP or CIDR from the blacklist.
	// Remove 从黑名单中移除 IP 或 CIDR。
	Remove(cidr string) error

	// Clear removes all entries from the blacklist.
	// Clear 移除黑名单中的所有条目。
	Clear() error

	// Contains checks if an IP is in the blacklist.
	// Contains 检查 IP 是否在黑名单中。
	Contains(ip string) (bool, error)

	// List returns a list of blacklisted IPs.
	// List 返回黑名单 IP 的列表。
	List(limit int, search string) ([]BlockedIP, int, error)
}

type blacklistImpl struct {
	mgr      ManagerInterface
	eventBus EventBus
}

func (b *blacklistImpl) Add(cidr string) error {
	if err := b.mgr.AddBlacklistIP(cidr); err != nil {
		return err
	}
	if b.eventBus != nil {
		b.eventBus.Publish(NewEvent(EventTypeRateLimitBlock, "manual_blacklist", cidr))
	}
	return nil
}

func (b *blacklistImpl) AddWithDuration(cidr string, duration time.Duration) error {
	if err := b.mgr.AddDynamicBlacklistIP(cidr, duration); err != nil {
		return err
	}
	if b.eventBus != nil {
		b.eventBus.Publish(NewEvent(EventTypeRateLimitBlock, "manual_blacklist_duration", cidr))
	}
	return nil
}

func (b *blacklistImpl) AddWithFile(cidr string, file string) error {
	if err := b.mgr.AddBlacklistIPWithFile(cidr, file); err != nil {
		return err
	}
	if b.eventBus != nil {
		b.eventBus.Publish(NewEvent(EventTypeRateLimitBlock, "manual_blacklist_file", cidr))
	}
	return nil
}

func (b *blacklistImpl) Remove(cidr string) error {
	return b.mgr.RemoveBlacklistIP(cidr)
}

func (b *blacklistImpl) Clear() error {
	return b.mgr.ClearBlacklist()
}

func (b *blacklistImpl) Contains(ip string) (bool, error) {
	return b.mgr.IsIPInBlacklist(ip)
}

func (b *blacklistImpl) List(limit int, search string) ([]BlockedIP, int, error) {
	return b.mgr.ListBlacklistIPs(limit, search)
}
