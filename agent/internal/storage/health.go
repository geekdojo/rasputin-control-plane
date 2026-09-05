package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The write probe — the half of a health check that presence cannot do
// (design/storage.md §4.4, geekdojo/geekdojo-brain#398).
//
// On e3bench (2026-09-02) a USB target began throwing `device offline error`
// on writes and went on answering enumeration for some time afterwards. A
// check that lists, mounts and statfs's a disk would have called that disk
// healthy. So the health poll asks for this on top of inspect: create a small
// file, fsync it, read it back, delete it, fsync the directory. Every one of
// those is an operation a backup run performs, and the first of them the disk
// refuses is the answer.
//
// What it cannot promise is stated where the operator reads the result
// (proto.BackupTargetHealthCaveat): a disk that takes 4 KiB at 03:55 can still
// refuse a gigabyte at 04:00.

const (
	// writeProbeBytes is the probe file's size. Small on purpose: a probe
	// that costs more than a directory entry and one block is a probe an
	// operator would be right to turn off on spinning media it wakes every
	// five minutes.
	writeProbeBytes = 4096
	// writeProbeBudget bounds the probe inside the inspect work budget
	// (proto.StorageInspectWork, 60 s) so that a disk which hangs on fsync —
	// the other e3bench symptom, `device descriptor read/64, error -110` — is
	// reported as a failed probe instead of a silent RPC timeout.
	writeProbeBudget = 20 * time.Second
)

// WriteProbe performs the write probe under mountPath and reports what
// happened. It never returns an error: a failed probe is a finding, not a
// fault in the prober, and it is carried in the result's Detail.
//
// The probe works in proto.StorageHealthProbeDir, a dot-directory at the mount
// root the archive walker ignores, under a random file name so two probes
// that overlap (a health poll and a manual re-check) cannot read each other's
// bytes. A file left behind by a probe that crashed mid-way is swept on the
// next one.
func WriteProbe(ctx context.Context, mountPath string) *proto.StorageWriteProbe {
	started := time.Now()
	res := &proto.StorageWriteProbe{}
	if strings.TrimSpace(mountPath) == "" {
		res.Detail = "no mount path to probe"
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, writeProbeBudget)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- writeProbeOnce(mountPath) }()
	select {
	case err := <-done:
		res.DurationMs = time.Since(started).Milliseconds()
		if err != nil {
			res.Detail = err.Error()
			return res
		}
		res.OK = true
		res.Detail = fmt.Sprintf("wrote, fsynced, read back and deleted a %d-byte file under %s in %d ms",
			writeProbeBytes, filepath.Join(mountPath, proto.StorageHealthProbeDir), res.DurationMs)
		return res
	case <-ctx.Done():
		// The goroutine is left to finish or hang on its own: a syscall that
		// has stopped returning on a dead disk cannot be cancelled from here,
		// and the answer the api needs is "this disk did not complete a
		// 4 KiB write in twenty seconds", which is already known.
		res.DurationMs = time.Since(started).Milliseconds()
		res.Detail = fmt.Sprintf("the write probe did not complete within %s — the disk is not taking writes in any useful time", writeProbeBudget)
		return res
	}
}

// writeProbeOnce is the probe body. Each failure names the operation that
// failed, because "unwritable" on its own does not tell an operator whether
// the disk is full, read-only, or gone.
func writeProbeOnce(mountPath string) error {
	dir := filepath.Join(mountPath, proto.StorageHealthProbeDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	sweepProbeDir(dir)

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("random probe name: %w", err)
	}
	path := filepath.Join(dir, "probe-"+hex.EncodeToString(suffix[:]))
	payload := make([]byte, writeProbeBytes)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("random probe payload: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create probe file: %w", err)
	}
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write probe file: %w", err)
	}
	if err := f.Sync(); err != nil {
		// THE e3bench failure. A write that lands in the page cache and an
		// fsync that returns EIO is a disk that has stopped taking writes,
		// and it is only visible here.
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("fsync probe file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close probe file: %w", err)
	}
	back, err := os.ReadFile(path)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("read probe file back: %w", err)
	}
	if !bytes.Equal(back, payload) {
		_ = os.Remove(path)
		return errors.New("the probe file read back differs from what was written — the disk is returning wrong data")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete probe file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}

// sweepProbeDir removes probe files an earlier, interrupted probe left
// behind. Best-effort and silent: a leftover is bounded at one small file per
// crash, and a failure to remove it will surface as this probe's own error a
// moment later if the disk is the reason.
func sweepProbeDir(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "probe-") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
