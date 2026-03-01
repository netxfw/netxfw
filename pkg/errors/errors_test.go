package errors

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	sentinelErrors := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrInvalidIP", ErrInvalidIP, "invalid IP address"},
		{"ErrInvalidCIDR", ErrInvalidCIDR, "invalid CIDR notation"},
		{"ErrInvalidPort", ErrInvalidPort, "invalid port number"},
		{"ErrInvalidTTL", ErrInvalidTTL, "invalid TTL value"},
		{"ErrInvalidRate", ErrInvalidRate, "invalid rate limit value"},
		{"ErrInvalidBurst", ErrInvalidBurst, "invalid burst value"},
		{"ErrInvalidAction", ErrInvalidAction, "invalid action"},
		{"ErrInvalidProtocol", ErrInvalidProtocol, "invalid protocol"},
		{"ErrInvalidFilePath", ErrInvalidFilePath, "invalid file path"},
		{"ErrFileNotFound", ErrFileNotFound, "file not found"},
		{"ErrFileTooLarge", ErrFileTooLarge, "file too large"},
		{"ErrPermissionDenied", ErrPermissionDenied, "permission denied"},
		{"ErrConfigNotFound", ErrConfigNotFound, "config not found"},
		{"ErrConfigInvalid", ErrConfigInvalid, "invalid configuration"},
		{"ErrMapNotFound", ErrMapNotFound, "BPF map not found"},
		{"ErrMapOperationFailed", ErrMapOperationFailed, "BPF map operation failed"},
		{"ErrXDPLoadFailed", ErrXDPLoadFailed, "XDP program load failed"},
		{"ErrXDPAttachFailed", ErrXDPAttachFailed, "XDP program attach failed"},
		{"ErrDaemonNotRunning", ErrDaemonNotRunning, "daemon not running"},
		{"ErrDaemonAlreadyRunning", ErrDaemonAlreadyRunning, "daemon already running"},
		{"ErrTimeout", ErrTimeout, "operation timeout"},
		{"ErrCanceled", ErrCanceled, "operation canceled"},
		{"ErrNotImplemented", ErrNotImplemented, "not implemented"},
	}

	for _, tc := range sentinelErrors {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Errorf("%s is nil", tc.name)
				return
			}
			if tc.err.Error() != tc.msg {
				t.Errorf("%s: got %q, want %q", tc.name, tc.err.Error(), tc.msg)
			}
		})
	}
}

func TestNewIPError(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "IPv4 invalid",
			ip:   "256.1.1.1",
			want: "invalid IP address: 256.1.1.1",
		},
		{
			name: "IPv6 invalid",
			ip:   "not::valid::ipv6",
			want: "invalid IP address: not::valid::ipv6",
		},
		{
			name: "empty IP",
			ip:   "",
			want: "invalid IP address: ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewIPError(tc.ip)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrInvalidIP) {
				t.Errorf("error should wrap ErrInvalidIP")
			}
		})
	}
}

func TestNewCIDRError(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want string
	}{
		{
			name: "invalid CIDR",
			cidr: "192.168.1.0/33",
			want: "invalid CIDR notation: 192.168.1.0/33",
		},
		{
			name: "missing prefix",
			cidr: "192.168.1.0",
			want: "invalid CIDR notation: 192.168.1.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewCIDRError(tc.cidr)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrInvalidCIDR) {
				t.Errorf("error should wrap ErrInvalidCIDR")
			}
		})
	}
}

func TestNewPortError(t *testing.T) {
	tests := []struct {
		name string
		port int
		want string
	}{
		{
			name: "negative port",
			port: -1,
			want: "invalid port number: -1",
		},
		{
			name: "port too large",
			port: 65536,
			want: "invalid port number: 65536",
		},
		{
			name: "zero port",
			port: 0,
			want: "invalid port number: 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewPortError(tc.port)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrInvalidPort) {
				t.Errorf("error should wrap ErrInvalidPort")
			}
		})
	}
}

func TestNewTTLError(t *testing.T) {
	tests := []struct {
		name string
		ttl  string
		want string
	}{
		{
			name: "negative TTL",
			ttl:  "-1h",
			want: "invalid TTL value: -1h",
		},
		{
			name: "invalid format",
			ttl:  "invalid",
			want: "invalid TTL value: invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewTTLError(tc.ttl)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrInvalidTTL) {
				t.Errorf("error should wrap ErrInvalidTTL")
			}
		})
	}
}

func TestNewFileError(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		reason error
		want   string
	}{
		{
			name:   "file not found",
			path:   "/nonexistent/file.txt",
			reason: errors.New("no such file"),
			want:   "file not found: /nonexistent/file.txt: no such file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewFileError(tc.path, tc.reason)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrFileNotFound) {
				t.Errorf("error should wrap ErrFileNotFound")
			}
		})
	}
}

func TestNewMapError(t *testing.T) {
	tests := []struct {
		name    string
		mapName string
		op      string
		cause   error
		want    string
	}{
		{
			name:    "map operation failed",
			mapName: "test_map",
			op:      "update",
			cause:   errors.New("permission denied"),
			want:    "BPF map operation failed: map=test_map op=update: permission denied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewMapError(tc.mapName, tc.op, tc.cause)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrMapOperationFailed) {
				t.Errorf("error should wrap ErrMapOperationFailed")
			}
		})
	}
}

func TestNewConfigError(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value interface{}
		want  string
	}{
		{
			name:  "invalid config field",
			field: "port",
			value: -1,
			want:  "invalid configuration: field=port value=-1",
		},
		{
			name:  "invalid string field",
			field: "bind",
			value: "invalid",
			want:  "invalid configuration: field=bind value=invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewConfigError(tc.field, tc.value)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Errorf("got %q, want %q", err.Error(), tc.want)
			}
			if !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("error should wrap ErrConfigInvalid")
			}
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	t.Run("wrap and unwrap IP error", func(t *testing.T) {
		err := NewIPError("invalid.ip")
		if !errors.Is(err, ErrInvalidIP) {
			t.Error("errors.Is failed to match ErrInvalidIP")
		}
	})

	t.Run("wrap and unwrap CIDR error", func(t *testing.T) {
		err := NewCIDRError("invalid.cidr")
		if !errors.Is(err, ErrInvalidCIDR) {
			t.Error("errors.Is failed to match ErrInvalidCIDR")
		}
	})

	t.Run("wrap and unwrap Port error", func(t *testing.T) {
		err := NewPortError(99999)
		if !errors.Is(err, ErrInvalidPort) {
			t.Error("errors.Is failed to match ErrInvalidPort")
		}
	})

	t.Run("wrap and unwrap TTL error", func(t *testing.T) {
		err := NewTTLError("invalid")
		if !errors.Is(err, ErrInvalidTTL) {
			t.Error("errors.Is failed to match ErrInvalidTTL")
		}
	})

	t.Run("wrap and unwrap File error", func(t *testing.T) {
		err := NewFileError("/path/to/file", errors.New("test"))
		if !errors.Is(err, ErrFileNotFound) {
			t.Error("errors.Is failed to match ErrFileNotFound")
		}
	})

	t.Run("wrap and unwrap Map error", func(t *testing.T) {
		err := NewMapError("test_map", "update", errors.New("test"))
		if !errors.Is(err, ErrMapOperationFailed) {
			t.Error("errors.Is failed to match ErrMapOperationFailed")
		}
	})

	t.Run("wrap and unwrap Config error", func(t *testing.T) {
		err := NewConfigError("field", "value")
		if !errors.Is(err, ErrConfigInvalid) {
			t.Error("errors.Is failed to match ErrConfigInvalid")
		}
	})
}

func TestErrorComparison(t *testing.T) {
	t.Run("same sentinel errors are equal", func(t *testing.T) {
		if ErrInvalidIP != ErrInvalidIP {
			t.Error("same sentinel errors should be equal")
		}
	})

	t.Run("different sentinel errors are not equal", func(t *testing.T) {
		if ErrInvalidIP == ErrInvalidCIDR {
			t.Error("different sentinel errors should not be equal")
		}
	})
}
