// Package xdp defines the datapath/XDP module boundary.
//
// New datapath implementation work lands in this tree. External callers should
// depend on the focused sibling subpackages such as lifecycle, maps, programs,
// plugins, stats, health, and sync. Backend-specific code is isolated behind
// adapter bridges instead of leaking through the datapath package boundary.
package xdp
