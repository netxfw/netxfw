package sdk

import "sync"

// SDK provides a structured high-level API for interacting with NetXFW.
// SDK 提供了一个结构化的高级 API，用于与 NetXFW 交互。
type SDK struct {
	Blacklist BlacklistAPI
	Whitelist WhitelistAPI
	Rule      RuleAPI
	Stats     StatsAPI
	Security  SecurityAPI
	Sync      SyncAPI
	Conntrack ConntrackAPI
	EventBus  EventBus
	Store     KVStore
	mgr       ManagerInterface
	// Future extensions: Logger, Metrics, Config, Health
}

// KVStore defines a simple key-value store for inter-plugin communication.
// KVStore 为插件间通信定义了一个简单的键值存储。
type KVStore interface {
	Set(key string, value interface{})
	Get(key string) (interface{}, bool)
	Delete(key string)
}

type kvStoreImpl struct {
	data sync.Map
}

func (s *kvStoreImpl) Set(key string, value interface{}) {
	s.data.Store(key, value)
}

func (s *kvStoreImpl) Get(key string) (interface{}, bool) {
	return s.data.Load(key)
}

func (s *kvStoreImpl) Delete(key string) {
	s.data.Delete(key)
}

// NewSDK creates a new SDK instance.
// NewSDK 创建一个新的 SDK 实例。
func NewSDK(mgr ManagerInterface) *SDK {
	eb := NewEventBus()
	return &SDK{
		Blacklist: &blacklistImpl{mgr: mgr, eventBus: eb},
		Whitelist: &whitelistImpl{mgr: mgr},
		Rule:      &ruleImpl{mgr: mgr},
		Stats:     &statsImpl{mgr: mgr},
		Security:  &securityImpl{mgr: mgr},
		Sync:      &syncImpl{mgr: mgr},
		Conntrack: &conntrackImpl{mgr: mgr},
		EventBus:  eb,
		Store:     &kvStoreImpl{},
		mgr:       mgr,
	}
}

// GetManager returns the underlying ManagerInterface.
// Use this only when necessary for low-level operations not yet covered by the SDK.
// GetManager 返回底层的 ManagerInterface。
// 仅在 SDK 尚未覆盖的低级操作需要时使用此方法。
func (s *SDK) GetManager() ManagerInterface {
	return s.mgr
}
