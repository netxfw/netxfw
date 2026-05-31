package config

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	SetDefaultLogDirCreationEnabled(false)
	exitCode := m.Run()
	SetDefaultLogDirCreationEnabled(true)
	os.Exit(exitCode)
}
