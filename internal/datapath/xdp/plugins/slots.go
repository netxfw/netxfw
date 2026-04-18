package plugins

import (
	"fmt"

	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
)

const (
	SlotStart = backendxdp.ProgramIndexPluginStart
	SlotEnd   = backendxdp.ProgramIndexPluginEnd
)

// ValidateSlot checks whether an index is inside the supported plugin slot range.
func ValidateSlot(index int) error {
	if index < SlotStart || index > SlotEnd {
		return fmt.Errorf("invalid index: %d (must be between %d and %d)", index, SlotStart, SlotEnd)
	}
	return nil
}

// SlotRange returns the supported datapath plugin slot range.
func SlotRange() domaindatapath.SlotRange {
	return domaindatapath.SlotRange{
		Start: SlotStart,
		End:   SlotEnd,
	}
}

// ListSlots returns the current datapath plugin slot occupancy.
func ListSlots(manager *backendxdp.Manager) ([]domaindatapath.SlotStatus, error) {
	if manager == nil {
		return nil, fmt.Errorf("manager is nil")
	}

	slots := make([]domaindatapath.SlotStatus, 0, SlotEnd-SlotStart+1)
	for i := SlotStart; i <= SlotEnd; i++ {
		var progID uint32
		slot := domaindatapath.SlotStatus{Index: i}
		if err := manager.JmpTable().Lookup(uint32(i), &progID); err == nil {
			slot.ProgramID = progID
			slot.Occupied = true
		}
		slots = append(slots, slot)
	}
	return slots, nil
}
