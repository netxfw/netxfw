package config

import (
	"errors"
	"testing"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

type stubRuntimeSyncPort struct {
	syncFromFilesErr   error
	syncToFilesErr     error
	verifyAndRepairErr error
}

func (s stubRuntimeSyncPort) SyncFromFiles(_ *domainconfig.Config, _ bool) error {
	return s.syncFromFilesErr
}

func (s stubRuntimeSyncPort) SyncToFiles(_ *domainconfig.Config) error {
	return s.syncToFilesErr
}

func (s stubRuntimeSyncPort) VerifyAndRepair(_ *domainconfig.Config) error {
	return s.verifyAndRepairErr
}

func TestExecutorExecuteRejectsNilManager(t *testing.T) {
	err := NewExecutor().Execute(Plan{Mode: ModeConfigToRuntime}, nil, &domainconfig.Config{})
	if err == nil || err.Error() != "manager is nil" {
		t.Fatalf("expected manager is nil error, got %v", err)
	}
}

func TestExecutorExecuteRejectsUnknownMode(t *testing.T) {
	err := NewExecutor().Execute(Plan{Mode: Mode("unknown_mode")}, stubRuntimeSyncPort{}, &domainconfig.Config{})
	if err == nil || err.Error() != "unknown reconcile mode: unknown_mode" {
		t.Fatalf("expected unknown mode error, got %v", err)
	}
}

func TestExecutorExecutePropagatesConfigToRuntimeError(t *testing.T) {
	want := errors.New("sync from files failed")
	err := NewExecutor().Execute(
		Plan{Mode: ModeConfigToRuntime, Overwrite: true},
		stubRuntimeSyncPort{syncFromFilesErr: want},
		&domainconfig.Config{},
	)
	if !errors.Is(err, want) {
		t.Fatalf("expected propagated sync from files error, got %v", err)
	}
}

func TestExecutorExecutePropagatesRuntimeToConfigError(t *testing.T) {
	want := errors.New("sync to files failed")
	err := NewExecutor().Execute(
		Plan{Mode: ModeRuntimeToConfig},
		stubRuntimeSyncPort{syncToFilesErr: want},
		&domainconfig.Config{},
	)
	if !errors.Is(err, want) {
		t.Fatalf("expected propagated sync to files error, got %v", err)
	}
}

func TestExecutorExecutePropagatesVerifyAndRepairError(t *testing.T) {
	want := errors.New("verify and repair failed")
	err := NewExecutor().Execute(
		Plan{Mode: ModeVerifyAndRepair},
		stubRuntimeSyncPort{verifyAndRepairErr: want},
		&domainconfig.Config{},
	)
	if !errors.Is(err, want) {
		t.Fatalf("expected propagated verify and repair error, got %v", err)
	}
}
