package logengine

import "time"

// LogEvent represents a single log line with metadata.
type LogEvent struct {
	Line      string
	Source    string    // Filename or custom tag
	Timestamp time.Time // When we read it
}
