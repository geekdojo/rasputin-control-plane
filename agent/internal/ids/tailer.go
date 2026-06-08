package ids

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// PollInterval is how often the tailer wakes to check for new bytes when
// it's caught up to EOF, or to re-open a rotated/missing file. A var (not
// a const) so tests can shrink it. 200ms is a compromise: ET Open under
// a scan can fire many alerts per second, and we want the controlplane
// to feel real-time, but we don't want the agent's idle CPU drawing
// attention on the firewall's modest N100.
var PollInterval = 200 * time.Millisecond

// Tailer follows a single log file as new lines are appended, surfacing
// each line on Lines(). It handles three real-world conditions snort
// produces on OpenWrt:
//
//   - the file doesn't exist yet (snort hasn't logged its first alert
//     since startup — common on a freshly-booted firewall)
//   - the file is rotated: snort renames alert_fast.txt to
//     alert_fast.txt.1 and starts a new alert_fast.txt
//   - the file is truncated: rarer, but logrotate-style cleanup might
//     do this
//
// Detection is by file size compared to our last read offset. If size <
// offset, the file rotated/truncated and we reopen from the start. If
// stat fails with ENOENT we treat it the same way.
//
// On startup the tailer seeks to EOF of an existing file — we don't
// replay backlog. Operators can `cat /var/log/snort/alert_fast.txt` on
// the firewall for history.
type Tailer struct {
	path string
	out  chan string

	mu     sync.Mutex // guards f + offset across reopen
	f      *os.File
	offset int64
}

// NewTailer builds (but doesn't start) a tailer for path.
func NewTailer(path string) *Tailer {
	return &Tailer{
		path: path,
		out:  make(chan string, 256), // bounded — publisher's coalescer drains
	}
}

// Lines returns the channel new log lines arrive on. Closed when Run exits.
func (t *Tailer) Lines() <-chan string { return t.out }

// Run blocks reading lines until ctx is cancelled. Errors that aren't
// "file is missing/rotated" are logged and the tailer keeps trying — we
// don't want a transient permission glitch to take down the IDS pipeline
// for the life of the agent.
func (t *Tailer) Run(ctx context.Context) {
	defer close(t.out)

	t.openSeekEnd(ctx) // best-effort initial open

	tick := time.NewTicker(PollInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			t.closeFile()
			return
		case <-tick.C:
			if err := t.tickOnce(ctx); err != nil {
				log.Printf("ids/tailer: %v", err)
			}
		}
	}
}

func (t *Tailer) tickOnce(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.f == nil {
		// Try to open. If it still doesn't exist, that's fine — snort
		// hasn't written anything yet. We'll try again next tick.
		f, err := os.Open(t.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		t.f = f
		t.offset = 0 // fresh file → read from the beginning
	}

	// Rotation/truncation check: if the on-disk file is smaller than our
	// recorded offset, the file we're holding has been replaced or
	// truncated. Reopen from the start.
	st, err := os.Stat(t.path)
	if errors.Is(err, os.ErrNotExist) {
		// snort renamed alert_fast.txt and hasn't created a new one yet —
		// close our handle to the (now-orphan) file and try again later.
		t.closeFileLocked()
		return nil
	} else if err != nil {
		return err
	}
	if st.Size() < t.offset {
		// Rotated (typical: file is now empty, size=0) or truncated.
		// Reopen the new file and read from offset 0.
		t.closeFileLocked()
		f, err := os.Open(t.path)
		if err != nil {
			return err
		}
		t.f = f
		t.offset = 0
	}

	// Read everything from t.offset to EOF.
	if _, err := t.f.Seek(t.offset, io.SeekStart); err != nil {
		return err
	}
	br := bufio.NewReader(t.f)
	for {
		if ctx.Err() != nil {
			return nil
		}
		line, err := br.ReadString('\n')
		if line != "" {
			t.offset += int64(len(line))
			select {
			case t.out <- line:
			case <-ctx.Done():
				return nil
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// openSeekEnd opens the file (if present) and seeks to EOF, so the first
// tick reports only newly-appended lines. Best-effort — silent on
// ENOENT, errors otherwise.
func (t *Tailer) openSeekEnd(_ context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, err := os.Open(t.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("ids/tailer: initial open %s: %v", t.path, err)
		}
		return
	}
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		log.Printf("ids/tailer: seek end %s: %v", t.path, err)
		_ = f.Close()
		return
	}
	t.f = f
	t.offset = end
}

func (t *Tailer) closeFile() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeFileLocked()
}

func (t *Tailer) closeFileLocked() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}
