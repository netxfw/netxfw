package services

import "github.com/netxfw/netxfw/internal/application/ports"

// RuntimeService orchestrates plugin lifecycle through stable ports.
type RuntimeService struct {
	plugin ports.PluginPort
}

func NewRuntimeService(plugin ports.PluginPort) *RuntimeService {
	return &RuntimeService{plugin: plugin}
}

func (s *RuntimeService) Init() error {
	if s.plugin == nil {
		return nil
	}
	return s.plugin.Init()
}

func (s *RuntimeService) Start() error {
	if s.plugin == nil {
		return nil
	}
	return s.plugin.Start()
}

func (s *RuntimeService) Reload() error {
	if s.plugin == nil {
		return nil
	}
	return s.plugin.Reload()
}

func (s *RuntimeService) Stop() error {
	if s.plugin == nil {
		return nil
	}
	return s.plugin.Stop()
}
