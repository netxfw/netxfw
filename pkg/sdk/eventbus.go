package sdk

import (
	"sync"
	"time"
)

// EventType defines the type of event.
type EventType string

const (
	// EventTypeRateLimitBlock is triggered when an IP is automatically blocked due to rate limiting.
	EventTypeRateLimitBlock EventType = "rate_limit_block"
	// EventTypeConfigReload is triggered when the configuration is reloaded.
	EventTypeConfigReload EventType = "config_reload"
)

// Event represents a system event.
type Event struct {
	Type      EventType
	Payload   any
	Timestamp int64
	Source    string
}

// NewEvent creates a new event with the current timestamp.
func NewEvent(eventType EventType, source string, payload any) Event {
	return Event{
		Type:      eventType,
		Source:    source,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}
}

// EventHandler is a function that handles an event.
type EventHandler func(event Event)

// EventBus defines the interface for the system event bus.
type EventBus interface {
	// Subscribe registers a handler for a specific event type.
	Subscribe(eventType EventType, handler EventHandler)
	// Unsubscribe removes a handler for a specific event type.
	Unsubscribe(eventType EventType, handler EventHandler)
	// Publish publishes an event to all subscribers.
	Publish(event Event)
}

// DefaultEventBus is a simple in-memory event bus implementation.
type DefaultEventBus struct {
	handlers map[EventType][]EventHandler
	mu       sync.RWMutex
}

// NewEventBus creates a new DefaultEventBus.
func NewEventBus() *DefaultEventBus {
	return &DefaultEventBus{
		handlers: make(map[EventType][]EventHandler),
	}
}

// Subscribe registers a handler for a specific event type.
func (b *DefaultEventBus) Subscribe(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Unsubscribe removes a handler.
func (b *DefaultEventBus) Unsubscribe(eventType EventType, handler EventHandler) {
	// Implementation simplified for now
}

// Publish publishes an event to all subscribers.
func (b *DefaultEventBus) Publish(event Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if handlers, ok := b.handlers[event.Type]; ok {
		for _, handler := range handlers {
			// Execute handler in a separate goroutine to avoid blocking the publisher
			go handler(event)
		}
	}
}
