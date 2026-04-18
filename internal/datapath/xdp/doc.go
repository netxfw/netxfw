// Package xdp defines the datapath/XDP module boundary.
//
// New datapath implementation work lands in this tree. The preserved backend
// implementation now lives under internal/datapath/xdp/backend while
// callers migrate toward the narrower facades in the sibling subpackages.
package xdp
