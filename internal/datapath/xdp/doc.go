// Package xdp defines the datapath/XDP module boundary.
//
// New datapath implementation work lands in this tree. External callers should
// depend on the focused sibling subpackages such as lifecycle, maps, programs,
// plugins, stats, health, and sync. These packages own the datapath-facing
// handles, DTOs, and helper APIs directly over the backend implementation.
package xdp
