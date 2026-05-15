//go:build integration


package xdp

import "testing"

func TestManagerCloseIsIdempotentOnZeroValue(t *testing.T) {
	mgr := &Manager{}

	if err := mgr.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
}
