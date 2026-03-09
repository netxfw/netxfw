package sdk

import "time"

// BlacklistImpl implements BlacklistAPI interface.
// BlacklistImpl 实现 BlacklistAPI 接口。
type BlacklistImpl struct {
	mgr      ManagerInterface
	eventBus EventBus
}

func (b *BlacklistImpl) Add(cidr string) error {
	if err := b.mgr.AddBlacklistIP(cidr); err != nil {
		return err
	}
	if b.eventBus != nil {
		b.eventBus.Publish(NewEvent(EventTypeRateLimitBlock, "manual_blacklist", cidr))
	}
	return nil
}

func (b *BlacklistImpl) AddWithDuration(cidr string, duration time.Duration) error {
	if err := b.mgr.AddDynamicBlacklistIP(cidr, duration); err != nil {
		return err
	}
	if b.eventBus != nil {
		b.eventBus.Publish(NewEvent(EventTypeRateLimitBlock, "manual_blacklist_duration", cidr))
	}
	return nil
}

func (b *BlacklistImpl) AddWithFile(cidr string, file string) error {
	if err := b.mgr.AddBlacklistIPWithFile(cidr, file); err != nil {
		return err
	}
	if b.eventBus != nil {
		b.eventBus.Publish(NewEvent(EventTypeRateLimitBlock, "manual_blacklist_file", cidr))
	}
	return nil
}

func (b *BlacklistImpl) Remove(cidr string) error {
	return b.mgr.RemoveBlacklistIP(cidr)
}

func (b *BlacklistImpl) RemoveDynamic(cidr string) error {
	return b.mgr.RemoveDynamicBlacklistIP(cidr)
}

func (b *BlacklistImpl) Clear() error {
	return b.mgr.ClearBlacklist()
}

func (b *BlacklistImpl) Contains(ip string) (bool, error) {
	return b.mgr.IsIPInBlacklist(ip)
}

func (b *BlacklistImpl) List(limit int, search string) ([]BlockedIP, int, error) {
	return b.mgr.ListBlacklistIPs(limit, search)
}
