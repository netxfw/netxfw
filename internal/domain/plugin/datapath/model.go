// Package datapath provides datapath functionality.
package datapath

// SlotRange defines the supported datapath plugin jump-table range.
type SlotRange struct {
	Start int
	End   int
}

// Descriptor describes a configured datapath plugin artifact.
type Descriptor struct {
	Path        string
	Index       int
	Enabled     bool
	Description string
}

// SlotStatus captures the current occupancy of a datapath plugin slot.
type SlotStatus struct {
	Index     int
	ProgramID uint32
	Occupied  bool
}

// LifecycleStatus captures the minimal datapath plugin lifecycle/read model.
type LifecycleStatus struct {
	Path      string
	Index     int
	Loaded    bool
	Healthy   bool
	ProgramID uint32
	Message   string
}

// Command describes a datapath plugin lifecycle request.
type Command struct {
	Action string
	Path   string
	Index  int
}
