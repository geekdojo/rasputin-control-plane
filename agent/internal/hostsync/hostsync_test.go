package hostsync

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWritesAndRefreshes(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	ips := []string{"192.168.1.50", "192.168.1.50", "192.168.1.77"} // unchanged, then changed
	resolve := func(name string, _ time.Duration) (string, error) {
		i := calls.Add(1) - 1
		if int(i) >= len(ips) {
			return ips[len(ips)-1], nil
		}
		return ips[i], nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// reloadCmd writes a marker each time it runs, so we can assert it fires on
	// every address change (first write + the change), not every tick.
	marker := filepath.Join(dir, "reload.count")
	reloadCmd := "printf x >> " + marker
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, reloadCmd, resolve)

	file := filepath.Join(dir, "rasputin.local")
	// First write: 192.168.1.50
	waitFor(t, func() bool { return readHost(file) == "192.168.1.50 rasputin.local\n" })
	// After the address changes, the file follows.
	waitFor(t, func() bool { return readHost(file) == "192.168.1.77 rasputin.local\n" })
	// reloadCmd ran on each change (first write + the change) = 2 markers,
	// not once per tick.
	waitFor(t, func() bool { return len(readHost(marker)) == 2 })
}

func TestRunNoopOnResolveError(t *testing.T) {
	dir := t.TempDir()
	resolve := func(string, time.Duration) (string, error) { return "", os.ErrDeadlineExceeded }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, "rasputin.local", dir, 10*time.Millisecond, "", resolve)
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "rasputin.local")); !os.IsNotExist(err) {
		t.Fatalf("expected no hosts file on resolve error, got err=%v", err)
	}
}

func readHost(file string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	return string(b)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
