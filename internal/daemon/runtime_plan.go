package daemon

// InterfaceReconcileOrder controls whether orphaned interfaces are detached
// before or after attaching the desired interface set.
type InterfaceReconcileOrder int

const (
	DetachBeforeAttach InterfaceReconcileOrder = iota
	DetachAfterAttach
)
