// Package ids subscribes to per-firewall IDS alerts on the NATS bus and
// persists them in a JSONL file the controlplane's Alloy tails, shipping
// to Loki for the UI's logs/IDS panel.
//
// We don't talk to Loki directly here — the existing Alloy
// loki.source.file is the canonical path for "rasputin emits a log
// line, get it to Loki." Keeps the api free of Loki's HTTP push API
// and reuses Slice 1.3 plumbing.
package ids

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Rotation defaults. Size-based not time-based: a quiet week-long
// firewall would otherwise produce no logs but still hit the rotate
// path. Tuned for "you can scroll a few days of alerts before Loki
// stops returning rows."
const (
	DefaultMaxBytes    int64 = 100 << 20 // 100 MB
	DefaultMaxBackups        = 5
)

// Writer appends one JSON line per IDS alert. The output line shape:
//
//	{"ts":"2026-06-08T14:23:45Z","nodeId":"fw-1","gid":1,"sid":2009582,
//	 "rev":5,"priority":2,"protocol":"TCP","srcAddr":"...","srcPort":...,
//	 "dstAddr":"...","dstPort":...,"classification":"...","message":"...",
//	 "raw":"<verbatim alert_fast line>"}
//
// Alloy's loki.source.file is configured to extract `nodeId` as a label
// (see obs.alloyConfigTmpl) so the UI can query `{job="rasputin-ids",
// node_id="fw-1"}` without pulling every node's alerts.
type Writer struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// NewWriter opens the IDS log file (creating it if necessary, creating
// parent dirs too) and returns a Writer ready for Write calls.
func NewWriter(path string) (*Writer, error) {
	return NewWriterWithLimits(path, DefaultMaxBytes, DefaultMaxBackups)
}

func NewWriterWithLimits(path string, maxBytes int64, maxBackups int) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("ids writer: mkdir parent: %w", err)
	}
	w := &Writer{path: path, maxBytes: maxBytes, maxBackups: maxBackups}
	if err := w.openAppend(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) openAppend() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("ids writer: open %s: %w", w.path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("ids writer: stat %s: %w", w.path, err)
	}
	w.f = f
	w.size = st.Size()
	return nil
}

// Write appends one JSON-line alert. If the file would exceed maxBytes,
// rotates first (rename + reopen). Safe for concurrent callers.
func (w *Writer) Write(ev *proto.IDSAlertEvt) error {
	if ev == nil {
		return errors.New("ids writer: nil event")
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("ids writer: marshal: %w", err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(line)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(line)
	if err != nil {
		return fmt.Errorf("ids writer: write: %w", err)
	}
	w.size += int64(n)
	return nil
}

// Close flushes the active file. Subsequent Writes return an error.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// rotateLocked closes the current file, shifts .N → .N+1 (dropping
// .maxBackups), renames current → .1, and reopens the live file.
// Caller must hold w.mu.
func (w *Writer) rotateLocked() error {
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("ids writer: close before rotate: %w", err)
	}
	w.f = nil

	// Shift .N → .N+1 from the back: .4 → .5, .3 → .4, ..., live → .1.
	// Drop the oldest by overwriting (os.Rename replaces target on POSIX).
	for i := w.maxBackups; i >= 1; i-- {
		src := backupPath(w.path, i)
		dst := backupPath(w.path, i+1)
		if i == w.maxBackups {
			// Oldest goes away (its .N+1 slot doesn't exist; we just delete).
			_ = os.Remove(src) // best-effort — missing is fine on early rotations
			continue
		}
		_ = os.Rename(src, dst) // best-effort: missing earlier slots are fine
	}
	// live → .1
	if err := os.Rename(w.path, backupPath(w.path, 1)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ids writer: rename live → .1: %w", err)
	}
	return w.openAppend()
}

func backupPath(base string, idx int) string {
	return fmt.Sprintf("%s.%d", base, idx)
}

// Compile-time assertion that Writer implements io.Closer.
var _ io.Closer = (*Writer)(nil)
