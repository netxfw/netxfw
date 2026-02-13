package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func generateRandomToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "netxfw_default_token_please_change"
	}
	return hex.EncodeToString(b)
}

func appendToFile(filePath, line string) {
	if filePath == "" {
		return
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	// Check if already exists
	content, err := os.ReadFile(filePath)
	if err == nil && strings.Contains(string(content), line) {
		return
	}

	f.WriteString(line + "\n")
}

func removeFromFile(filePath, line string) {
	if filePath == "" {
		return
	}
	input, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	lines := strings.Split(string(input), "\n")
	var newLines []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && trimmed != line {
			newLines = append(newLines, trimmed)
		}
	}

	os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

func parseIPPortAction(input string) (string, uint16, uint8, error) {
	// Format: IP:Port:Action or [IP]:Port:Action
	// Action: allow (1) or deny (2)

	// Handle IPv6 with brackets [::1]:80:allow or [::1]:80
	if strings.HasPrefix(input, "[") {
		endBracket := strings.Index(input, "]")
		if endBracket == -1 {
			return "", 0, 0, fmt.Errorf("invalid IPv6 format: missing ]")
		}
		ip := input[1:endBracket]
		rest := input[endBracket+1:]
		if strings.HasPrefix(rest, ":") {
			restParts := strings.Split(strings.TrimPrefix(rest, ":"), ":")
			if len(restParts) < 1 {
				return "", 0, 0, fmt.Errorf("missing port")
			}
			var port uint16
			fmt.Sscanf(restParts[0], "%d", &port)
			action := uint8(2) // Default deny
			if len(restParts) >= 2 {
				if restParts[1] == "allow" {
					action = 1
				} else if restParts[1] == "deny" {
					action = 2
				}
			}
			return ip, port, action, nil
		}
		return "", 0, 0, fmt.Errorf("invalid format after ]")
	}

	// Handle IPv4 or IPv6 without brackets
	parts := strings.Split(input, ":")
	if len(parts) < 2 {
		return "", 0, 0, fmt.Errorf("invalid format, expected IP:Port[:Action]")
	}

	// Check if it's IPv6 without brackets (multiple colons before the port)
	// Example: 2001:db8::1:80:allow
	if strings.Count(input, ":") > 2 {
		// Heuristic: Check last part
		last := parts[len(parts)-1]
		if last == "allow" || last == "deny" {
			if len(parts) < 3 {
				return "", 0, 0, fmt.Errorf("invalid IPv6 format without brackets")
			}
			action := uint8(2)
			if last == "allow" {
				action = 1
			}
			var port uint16
			fmt.Sscanf(parts[len(parts)-2], "%d", &port)
			ip := strings.Join(parts[:len(parts)-2], ":")
			return ip, port, action, nil
		} else {
			// No action specified: 2001:db8::1:80
			var port uint16
			fmt.Sscanf(parts[len(parts)-1], "%d", &port)
			ip := strings.Join(parts[:len(parts)-1], ":")
			return ip, port, 2, nil
		}
	}

	// Standard IPv4: 1.2.3.4:80[:allow]
	ip := parts[0]
	var port uint16
	fmt.Sscanf(parts[1], "%d", &port)
	action := uint8(2)
	if len(parts) >= 3 {
		if parts[2] == "allow" {
			action = 1
		}
	}
	return ip, port, action, nil
}
