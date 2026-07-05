package sdk

import (
	"reflect"
	"sync"
	"time"
)

type EventType string

const (
	EventTypeRateLimitBlock EventType = "rate_limit_block"
	EventTypeConfigReload   EventType = "config_reload"
)

type Event struct {
	Type      EventType
	Payload   any
	Timestamp int64
	Source    string
}

func NewEvent(eventType EventType, source string, payload any) Event {
	return Event{
		Type:      eventType,
		Source:    source,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}
}

type EventHandler func(event Event)

type CancelFunc func()

type EventBus interface {
	// Subscribe registers a handler for a specific event type.
	// Returns a CancelFunc that can be used to unsubscribe the handler.
	Subscribe(eventType EventType, handler EventHandler) CancelFunc
	// Unsubscribe removes a handler for a specific event type.
	Unsubscribe(eventType EventType, handler EventHandler)
	// Publish publishes an event to all subscribers.
	Publish(event Event)
}

type subscription struct {
	id      uint64
	handler EventHandler
}

type DefaultEventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]subscription
	nextID   uint64
}

func NewEventBus() *DefaultEventBus {
	return &DefaultEventBus{
		handlers: make(map[EventType][]subscription),
	}
}

func (b *DefaultEventBus) Subscribe(eventType EventType, handler EventHandler) CancelFunc {
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.handlers[eventType] = append(b.handlers[eventType], subscription{id: id, handler: handler})
	b.mu.Unlock()

	return func() {
		b.mu.Lock()
		subs := b.handlers[eventType]
		for i, sub := range subs {
			if sub.id == id {
				b.handlers[eventType] = append(subs[:i], subs[i+1:]...)
				if len(b.handlers[eventType]) == 0 {
					delete(b.handlers, eventType)
				}
				b.mu.Unlock()
				return
			}
		}
		b.mu.Unlock()
	}
}

func (b *DefaultEventBus) Unsubscribe(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.handlers[eventType]
	var filtered []subscription
	for _, sub := range subs {
		if reflect.ValueOf(sub.handler).Pointer() == reflect.ValueOf(handler).Pointer() {
			continue
		}
		filtered = append(filtered, sub)
	}
	if len(filtered) == 0 {
		delete(b.handlers, eventType)
	} else {
		b.handlers[eventType] = filtered
	}
}

func (b *DefaultEventBus) Publish(event Event) {
	b.mu.RLock()
	if len(b.handlers[event.Type]) == 0 {
		b.mu.RUnlock()
		return
	}
	subs := make([]subscription, len(b.handlers[event.Type]))
	copy(subs, b.handlers[event.Type])
	b.mu.RUnlock()

	for _, sub := range subs {
		sub.handler(event)
	}
}