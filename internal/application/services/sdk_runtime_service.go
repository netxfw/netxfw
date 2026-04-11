package services

import (
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// SDKRuntimeService centralizes SDK/config runtime access for command adapters.
type SDKRuntimeService struct{}

func NewSDKRuntimeService() *SDKRuntimeService {
	return &SDKRuntimeService{}
}

func (s *SDKRuntimeService) NewPinnedSDK() (*sdk.SDK, error) {
	return app.NewPinnedSDK()
}

func (s *SDKRuntimeService) LoadConfig() (*sdk.GlobalConfig, error) {
	return app.LoadConfig()
}
