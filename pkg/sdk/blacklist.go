package sdk

import "time"

// blacklistImpl implements BlacklistAPI interface.
// blacklistImpl 实现 BlacklistAPI 接口。
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
