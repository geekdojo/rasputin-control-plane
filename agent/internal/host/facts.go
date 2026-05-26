package host

import (
	"os"
	"time"
)

var startedAt = time.Now()

// Hostname returns the system hostname, or "" on error.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}

// Uptime returns how long the agent process has been running, rounded to
// the nearest second so the formatted output stays compact.
func Uptime() time.Duration {
	return time.Since(startedAt).Round(time.Second)
}
