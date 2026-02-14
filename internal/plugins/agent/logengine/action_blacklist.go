package logengine

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/livp123/netxfw/internal/xdp"
)

// ActionType defines the type of action
type ActionType int

const (
	ActionLog     ActionType = 0
	ActionDynamic ActionType = 1
	ActionStatic  ActionType = 2
)

// ActionHandler defines the interface for taking actions on matched IPs.
type ActionHandler interface {
	Block(ip netip.Addr, actionType ActionType, ttl time.Duration) error
	Stop()
}

// XDPActionHandler implements ActionHandler using the XDP manager asynchronously.
type XDPActionHandler struct {
	manager      xdp.ManagerInterface
	lockListFile string
	actionChan   chan actionRequest
	stopChan     chan struct{}
}

type actionRequest struct {
	ip         netip.Addr
	actionType ActionType
	ttl        time.Duration
}

// NewXDPActionHandler creates a new handler and starts the worker.
func NewXDPActionHandler(m xdp.ManagerInterface, lockListFile string) *XDPActionHandler {
	h := &XDPActionHandler{
		manager:      m,
		lockListFile: lockListFile,
		actionChan:   make(chan actionRequest, 1024), // Buffer for burst protection
		stopChan:     make(chan struct{}),
	}
	go h.run()
	return h
}

// Block queues the action for asynchronous execution.
func (h *XDPActionHandler) Block(ip netip.Addr, actionType ActionType, ttl time.Duration) error {
	select {
	case h.actionChan <- actionRequest{ip: ip, actionType: actionType, ttl: ttl}:
		return nil
	default:
		return fmt.Errorf("action queue full, dropping action for %s", ip)
	}
}

// Stop stops the background worker.
func (h *XDPActionHandler) Stop() {
	close(h.stopChan)
}

func (h *XDPActionHandler) run() {
	for {
		select {
		case <-h.stopChan:
			return
		case req := <-h.actionChan:
			h.execute(req)
		}
	}
}

func (h *XDPActionHandler) execute(req actionRequest) {
	if h.manager == nil {
		return
	}

	var err error
	switch req.actionType {
	case ActionStatic:
		err = h.manager.AddBlacklistIPWithFile(req.ip.String(), h.lockListFile)
	case ActionDynamic:
		err = h.manager.AddDynamicBlacklistIP(req.ip.String(), req.ttl)
	case ActionLog:
		// Logging is handled by the caller/pipeline
		return
	}

	if err != nil {
		fmt.Printf("❌ [AsyncAction] Failed to execute action for %s: %v\n", req.ip, err)
	}
}
