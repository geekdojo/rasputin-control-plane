package ids

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// DefaultAlertLogPath is where the firewall's snort.uc template writes
// alert_fast output when log_dir=/var/log/snort (the value 99-rasputin
// seeds). Exposed so tests + dev runs can override it.
const DefaultAlertLogPath = "/var/log/snort/alert_fast.txt"

// Run starts the agent's IDS pipeline for this node and blocks until
// ctx is cancelled. The shape is:
//
//	tailer → parser → publisher (proto.IDSAlertSubject(nodeID))
//
// Errors at the parser stage (unrecognized line shapes) are silently
// skipped — the operator's snort might emit a header line or a future
// snort version might add a field we don't model. We never block snort
// over a parse failure; the line is preserved in the source log on the
// firewall regardless. Publish errors are logged and skipped; the
// in-process NATS client buffers + reconnects on its own.
//
// On a path other than DefaultAlertLogPath (tests, dev), pass the
// override as the path arg. nodeID is the agent's stable identity (the
// same one published in metrics/heartbeats).
func Run(ctx context.Context, nc *nats.Conn, nodeID, path string) {
	if path == "" {
		path = DefaultAlertLogPath
	}
	subj := proto.IDSAlertSubject(nodeID)

	// Log a startup line so operators bisecting "is the IDS subsystem
	// even running?" can grep for it. The silent-start was a real DX
	// cost during the CWWK 2026-06-08 IDS bring-up — without a log
	// line we had to bisect with manual `echo >> alert_fast.txt` to
	// distinguish "tailer dead" from "agent v0.1.0 has no IDS at all"
	// from "snort not writing alert_fast.txt". This one line makes the
	// difference.
	log.Printf("ids: tailer started, path=%s, subject=%s", path, subj)

	tail := NewTailer(path)
	go tail.Run(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-tail.Lines():
			if !ok {
				// Tailer exited (ctx cancelled). Bail.
				return
			}
			ev, parsed, err := ParseAlertFast(nodeID, line, time.Now)
			if err != nil {
				log.Printf("ids: parse error (skipping line): %v", err)
				continue
			}
			if !parsed {
				continue
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				log.Printf("ids: marshal: %v", err)
				continue
			}
			if err := nc.Publish(subj, payload); err != nil {
				log.Printf("ids: publish: %v", err)
			}
		}
	}
}
