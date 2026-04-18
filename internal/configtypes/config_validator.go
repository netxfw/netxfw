package types

import (
	"net"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

type ValidationError = domainconfig.ValidationError
type ValidationWarning = domainconfig.ValidationWarning
type ValidationResult = domainconfig.ValidationResult

type ConfigValidator struct {
	inner *domainconfig.ConfigValidator
}

func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{inner: domainconfig.NewConfigValidator()}
}

func (v *ConfigValidator) ValidateSyntax(configData []byte) *ValidationResult {
	return v.inner.ValidateSyntax(configData)
}

func (v *ConfigValidator) Validate(cfg *GlobalConfig) *ValidationResult {
	return v.inner.Validate((*domainconfig.Config)(cfg))
}

func (v *ConfigValidator) networksOverlap(n1, n2 *net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
}

func ValidateConfig(configData []byte) (*ValidationResult, error) {
	return domainconfig.ValidateConfig(configData)
}

func ValidateConfigStruct(cfg *GlobalConfig) *ValidationResult {
	return domainconfig.ValidateConfigStruct((*domainconfig.Config)(cfg))
}
