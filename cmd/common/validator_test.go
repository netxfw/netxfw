package common

import (
	"os"
	"testing"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv4 CIDR", "192.168.1.0/24", false},
		{"Valid IPv6", "2001:db8::1", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false},
		{"Invalid IP", "invalid-ip", true},
		{"Empty IP", "", true},
		{"Invalid CIDR", "192.168.1.0/33", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIP(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"Valid port 0", 0, false},
		{"Valid port 80", 80, false},
		{"Valid port 443", 443, false},
		{"Valid port 65535", 65535, false},
		{"Invalid port -1", -1, true},
		{"Invalid port 65536", 65536, true},
		{"Invalid port 100000", 100000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
		want bool
	}{
		{"Valid port 0", 0, true},
		{"Valid port 80", 80, true},
		{"Valid port 443", 443, true},
		{"Valid port 65535", 65535, true},
		{"Invalid port -1", -1, false},
		{"Invalid port 65536", 65536, false},
		{"Invalid port 100000", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidPort(tt.port); got != tt.want {
				t.Errorf("IsValidPort(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestValidatePortNonZero(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"Invalid port 0", 0, true},
		{"Valid port 1", 1, false},
		{"Valid port 80", 80, false},
		{"Valid port 65535", 65535, false},
		{"Invalid port -1", -1, true},
		{"Invalid port 65536", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePortNonZero(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePortNonZero(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidateLimit(t *testing.T) {
	tests := []struct {
		name    string
		limit   int
		wantErr bool
	}{
		{"Valid limit 1", 1, false},
		{"Valid limit 100", 100, false},
		{"Valid limit 100000", 100000, false},
		{"Invalid limit 0", 0, true},
		{"Invalid limit -1", -1, true},
		{"Invalid limit 100001", 100001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLimit(tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLimit(%d) error = %v, wantErr %v", tt.limit, err, tt.wantErr)
			}
		})
	}
}

func TestValidateLimitSmall(t *testing.T) {
	tests := []struct {
		name    string
		limit   int
		wantErr bool
	}{
		{"Valid limit 1", 1, false},
		{"Valid limit 100", 100, false},
		{"Valid limit 10000", 10000, false},
		{"Invalid limit 0", 0, true},
		{"Invalid limit 10001", 10001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLimitSmall(tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLimitSmall(%d) error = %v, wantErr %v", tt.limit, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRateLimit(t *testing.T) {
	tests := []struct {
		name    string
		rate    uint64
		burst   uint64
		wantErr bool
	}{
		{"Valid rate and burst", 1000, 10000, false},
		{"Valid max rate", 1000000, 10000000, false},
		{"Invalid rate 0", 0, 10000, true},
		{"Invalid burst 0", 1000, 0, true},
		{"Invalid rate too high", 1000001, 10000, true},
		{"Invalid burst too high", 1000, 10000001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRateLimit(tt.rate, tt.burst)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRateLimit(%d, %d) error = %v, wantErr %v", tt.rate, tt.burst, err, tt.wantErr)
			}
		})
	}
}

func TestValidateExpiry(t *testing.T) {
	tests := []struct {
		name    string
		expiry  int
		wantErr bool
	}{
		{"Valid expiry 1 second", 1, false},
		{"Valid expiry 1 hour", 3600, false},
		{"Valid expiry 1 day", 86400, false},
		{"Valid expiry 365 days", 365 * 24 * 60 * 60, false},
		{"Invalid expiry 0", 0, true},
		{"Invalid expiry -1", -1, true},
		{"Invalid expiry too high", 365*24*60*60 + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExpiry(tt.expiry)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExpiry(%d) error = %v, wantErr %v", tt.expiry, err, tt.wantErr)
			}
		})
	}
}

func TestValidateImportFile(t *testing.T) {
	tmpDir := t.TempDir()

	validFile := tmpDir + "/valid.txt"
	if err := os.WriteFile(validFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	largeFile := tmpDir + "/large.txt"
	largeData := make([]byte, MaxImportFileSize+1)
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatalf("Failed to create large test file: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"Valid file", validFile, false},
		{"Non-existent file", tmpDir + "/nonexistent.txt", true},
		{"File too large", largeFile, true},
		{"Path traversal", "../../../etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateImportFile(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateImportFile(%s) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestParseAndValidateTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttlStr  string
		wantErr bool
	}{
		{"Valid 1 second", "1s", false},
		{"Valid 1 minute", "1m", false},
		{"Valid 1 hour", "1h", false},
		{"Valid 24 hours", "24h", false},
		{"Valid 365 days", "8760h", false},
		{"Empty TTL", "", true},
		{"Invalid format", "invalid", true},
		{"Too short (0)", "0s", true},
		{"Too short (500ms)", "500ms", true},
		{"Too long (> 365 days)", "8761h", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAndValidateTTL(tt.ttlStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAndValidateTTL(%q) error = %v, wantErr %v", tt.ttlStr, err, tt.wantErr)
			}
		})
	}
}

func TestParseLimitAndSearch(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		defaultLimit int
		wantLimit    int
		wantSearch   string
		wantErr      bool
	}{
		{"Empty args", []string{}, 100, 100, "", false},
		{"Only limit", []string{"50"}, 100, 50, "", false},
		{"Limit and search", []string{"50", "192.168"}, 100, 50, "192.168", false},
		{"Only search", []string{"192.168"}, 100, 100, "192.168", false},
		{"Invalid limit (0)", []string{"0"}, 100, 0, "", true},
		{"Invalid limit (too high)", []string{"200000"}, 100, 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, search, err := ParseLimitAndSearch(tt.args, tt.defaultLimit)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLimitAndSearch(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if limit != tt.wantLimit {
					t.Errorf("ParseLimitAndSearch(%v) limit = %d, want %d", tt.args, limit, tt.wantLimit)
				}
				if search != tt.wantSearch {
					t.Errorf("ParseLimitAndSearch(%v) search = %q, want %q", tt.args, search, tt.wantSearch)
				}
			}
		})
	}
}

func TestFilterIPPortRules(t *testing.T) {
	tests := []struct {
		name          string
		rules         map[string]string
		action        string
		expectedCount int
		expectedIPs   []string
	}{
		{
			name:          "Empty rules",
			rules:         map[string]string{},
			action:        "allow",
			expectedCount: 0,
			expectedIPs:   nil,
		},
		{
			name: "Filter allow rules",
			rules: map[string]string{
				"192.168.1.1:80":  "allow",
				"192.168.1.2:443": "deny",
				"10.0.0.1:22":     "allow",
			},
			action:        "allow",
			expectedCount: 2,
			expectedIPs:   []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name: "Filter deny rules",
			rules: map[string]string{
				"192.168.1.1:80":  "allow",
				"192.168.1.2:443": "deny",
				"10.0.0.1:22":     "allow",
			},
			action:        "deny",
			expectedCount: 1,
			expectedIPs:   []string{"192.168.1.2"},
		},
		{
			name: "No matching action",
			rules: map[string]string{
				"192.168.1.1:80": "allow",
			},
			action:        "deny",
			expectedCount: 0,
			expectedIPs:   nil,
		},
		{
			name: "Invalid port format",
			rules: map[string]string{
				"192.168.1.1:abc": "allow",
				"192.168.1.2:80":  "allow",
			},
			action:        "allow",
			expectedCount: 1,
			expectedIPs:   []string{"192.168.1.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterIPPortRules(tt.rules, tt.action)
			if len(result) != tt.expectedCount {
				t.Errorf("FilterIPPortRules() count = %d, want %d", len(result), tt.expectedCount)
			}
			if tt.expectedIPs != nil {
				foundIPs := make(map[string]bool)
				for _, r := range result {
					foundIPs[r.IP] = true
				}
				for _, expectedIP := range tt.expectedIPs {
					if !foundIPs[expectedIP] {
						t.Errorf("FilterIPPortRules() missing IP %s", expectedIP)
					}
				}
			}
		})
	}
}
