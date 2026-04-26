// Package runtime provides runtime functionality.
package runtime

// Kind identifies the runtime plugin criticality level.
type Kind string

const (
	KindCore      Kind = "core"
	KindExtension Kind = "extension"
)

// Descriptor describes a runtime plugin registered in the host.
type Descriptor struct {
	Name string
	Kind Kind
}

// Status captures the minimal runtime plugin health/read model.
type Status struct {
	Name    string
	Kind    Kind
	Enabled bool
	Running bool
	Healthy bool
	Message string
}
