package logengine_test

import (
	"strings"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
)

func TestRealWorldSSHLogs(t *testing.T) {
	logs := `
2026-02-11T09:00:17.733860+00:00 racknerd-e09af81 sshd[41960]: Failed password for invalid user admin from 165.22.205.152 port 54134 ssh2 
2026-02-11T09:00:18.305152+00:00 racknerd-e09af81 sshd[41960]: Connection closed by invalid user admin 165.22.205.152 port 54134 [preauth] 
2026-02-11T09:00:22.291900+00:00 racknerd-e09af81 sshd[42010]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=178.62.249.170  user=root 
2026-02-11T09:00:22.583625+00:00 racknerd-e09af81 sshd[42020]: Invalid user nagios from 161.35.148.113 port 43480 
2026-02-11T09:00:22.710292+00:00 racknerd-e09af81 sshd[42020]: pam_unix(sshd:auth): check pass; user unknown 
2026-02-11T09:00:22.710713+00:00 racknerd-e09af81 sshd[42020]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=161.35.148.113 
2026-02-11T09:00:24.118280+00:00 racknerd-e09af81 sshd[42010]: Failed password for root from 178.62.249.170 port 50776 ssh2 
2026-02-11T09:00:24.535388+00:00 racknerd-e09af81 sshd[42020]: Failed password for invalid user nagios from 161.35.148.113 port 43480 ssh2 
2026-02-11T09:00:25.878391+00:00 racknerd-e09af81 sshd[42010]: Connection closed by authenticating user root 178.62.249.170 port 50776 [preauth] 
2026-02-11T09:00:26.581373+00:00 racknerd-e09af81 sshd[42020]: Connection closed by invalid user nagios 161.35.148.113 port 43480 [preauth]
`
	extractor := logengine.NewIPExtractor()
	
	expectedIPs := map[string][]string{
		"165.22.205.152": {},
		"178.62.249.170": {},
		"161.35.148.113": {},
	}

	lines := strings.Split(strings.TrimSpace(logs), "\n")
	for i, line := range lines {
		ips := extractor.ExtractIPs(line)
		t.Logf("Line %d extracted: %v", i+1, ips)
		
		// Verify all extracted IPs are valid
		for _, ip := range ips {
			if !ip.IsValid() {
				t.Errorf("Line %d: Extracted invalid IP: %s", i+1, ip)
			}
			// Check if we expect this IP (simple check)
			s := ip.String()
			if _, ok := expectedIPs[s]; ok {
				expectedIPs[s] = append(expectedIPs[s], line)
			}
		}
	}

	// Verify we found all expected IPs
	for ip, occurrences := range expectedIPs {
		if len(occurrences) == 0 {
			t.Errorf("Expected IP %s was not found in any log line", ip)
		} else {
			t.Logf("✅ IP %s found in %d lines", ip, len(occurrences))
		}
	}
}
