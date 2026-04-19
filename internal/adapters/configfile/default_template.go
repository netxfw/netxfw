package configfile

import _ "embed"

// defaultConfigTOMLTemplate stores the built-in commented default config.
//
//go:embed default_config.toml
var defaultConfigTOMLTemplate string

// DefaultTemplate returns the built-in commented default config template.
func DefaultTemplate() string {
	return defaultConfigTOMLTemplate
}
