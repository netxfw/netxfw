package plugins

import (
	"fmt"

	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
)

const (
	SlotStart = 2
	SlotEnd   = 14
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
func ListSlots(manager interface {
	LookupPluginProgram(index int) (uint32, bool, error)
}) ([]domaindatapath.SlotStatus, error) {
	if manager == nil {
		return nil, fmt.Errorf("manager is nil")
	}

	slots := make([]domaindatapath.SlotStatus, 0, SlotEnd-SlotStart+1)
	for i := SlotStart; i <= SlotEnd; i++ {
		slot := domaindatapath.SlotStatus{Index: i}
		progID, loaded, err := manager.LookupPluginProgram(i)
		if err == nil && loaded {
			slot.ProgramID = progID
			slot.Occupied = true
		}
		slots = append(slots, slot)
	}
	return slots, nil
}
