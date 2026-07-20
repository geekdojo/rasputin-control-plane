package host

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Storage snapshots the persistent data partition for the register event:
// a statfs of dataPath plus the outcome keyword from the rasputin-os growpart
// breadcrumb log. Returns nil when neither yields anything (dev box, pre-
// breadcrumb image) so the register event reports unknown rather than zeros.
//
// Register cadence is deliberate: both values change materially only across a
// boot (the one-time growpart), and every boot re-registers. Live fill level
// is the disk_* metrics' job.
func Storage(dataPath, growpartLog string) *proto.StorageInfo {
	info := &proto.StorageInfo{Growpart: growpartOutcome(growpartLog)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if du, err := disk.UsageWithContext(ctx, dataPath); err == nil {
		info.PersistentTotalBytes = du.Total
		info.PersistentFreeBytes = du.Free
	}
	if info.PersistentTotalBytes == 0 && info.Growpart == "" {
		return nil
	}
	return info
}

// growpartOutcome returns the newest outcome keyword from the breadcrumb log
// (lines are "<ts> <keyword>: <detail>"), or "" if the log is absent or holds
// no parseable line. Scanned newest-first: rotation can leave a truncated
// first line, and the newest outcome is the node's current state. The keyword
// charset is validated rather than matched against a closed set, so a future
// OS-side keyword flows through without an agent rev.
func growpartOutcome(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// The writer bounds the file (rotates to ~32 KiB); cap what we scan anyway.
	if len(b) > 8192 {
		b = b[len(b)-8192:]
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		f := strings.Fields(lines[i])
		if len(f) < 2 || !strings.HasSuffix(f[1], ":") {
			continue
		}
		if kw := strings.TrimSuffix(f[1], ":"); isOutcomeWord(kw) {
			return kw
		}
	}
	return ""
}

func isOutcomeWord(s string) bool {
	if s == "" || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '-' {
			return false
		}
	}
	return true
}
