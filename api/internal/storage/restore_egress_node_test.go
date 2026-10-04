package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-514-08, TC-516-02: the restore egress mirrors the ingest — a credential
// only from its own node's key on the node listener, the same records, and no
// path attribute in any of them.
func TestRestoreEgressNodeEntry(t *testing.T) {
	var global bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&global)
	t.Cleanup(func() { log.SetOutput(prev) })

	r := newEgressRig(t)
	r.arm(mustSHA(r.sealed))
	const nodeA, nodeB = "n-compute", "n-other"
	g := backupxfer.Grant{Generation: r.genID, Member: r.member, NodeID: nodeA, JobID: "job-restore",
		MaxBytes: uint64(len(r.plain)), Use: backupxfer.UseRestore}
	cred, err := r.egress.Mint(g, time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	refusedAs := func(t *testing.T, err error, status int, code string) {
		t.Helper()
		var re *backupxfer.RefusedError
		if !errors.As(err, &re) || re.Status != status || re.Problem.Code != code {
			t.Fatalf("err = %v, want %d %s", err, status, code)
		}
	}
	warnsBefore := func() int { return len(r.logs.AtLevel(slog.LevelWarn)) }
	noPath := func(t *testing.T, rec slog.Record) {
		t.Helper()
		if v, ok := logkittest.Attr(rec, "path"); ok {
			t.Errorf("record %q carries path=%q", rec.Message, v)
		}
	}

	// (b) the node entry with no owner: refused before the one slot. Called
	// directly with a body that never ends — had it taken the slot or read
	// the body, this call would not return.
	body, bodyW := io.Pipe()
	t.Cleanup(func() { _ = bodyW.Close() })
	req := httptest.NewRequest(http.MethodGet, backupxfer.EgressPathPrefix+r.genID+"/"+r.member, body)
	req.Header.Set("Authorization", "Bearer "+cred)
	rw := httptest.NewRecorder()
	r.egress.ServeNode(rw, req, "")
	var p backupxfer.Problem
	if rw.Code != http.StatusInternalServerError || json.Unmarshal(rw.Body.Bytes(), &p) != nil || p.Code != backupxfer.CodeCredentialInvalid {
		t.Fatalf("(b) %d %s", rw.Code, rw.Body.String())
	}
	if errs := r.logs.AtLevel(slog.LevelError); len(errs) != 1 || !strings.Contains(errs[0].Message, "wiring fault") {
		t.Fatalf("(b) ERROR records:\n%s", r.logs.Text())
	}

	// (c) another node's key.
	w0 := warnsBefore()
	_, _, err = r.fetchAs(nodeB, cred)
	refusedAs(t, err, http.StatusForbidden, backupxfer.CodeCredentialScope)
	if warns := r.logs.AtLevel(slog.LevelWarn); len(warns)-w0 != 1 {
		t.Fatalf("(c) WARN records:\n%s", r.logs.Text())
	} else {
		last := warns[len(warns)-1]
		for k, want := range map[string]string{"presenting_node": nodeB, "grant_node": nodeA, "job_id": "job-restore"} {
			if v, _ := logkittest.Attr(last, k); v != want {
				t.Errorf("(c) %s = %q, want %q", k, v, want)
			}
		}
		noPath(t, last)
	}

	// (d) its own node's key: the plaintext, and the stream-served record.
	// That this proceeds at all is (b)'s slot left free.
	plain, _, err := r.fetchAs(nodeA, cred)
	if err != nil {
		t.Fatalf("(d) %v", err)
	}
	if !bytes.Equal(plain, r.plain) {
		t.Fatalf("(d) the stream is not the plaintext (%d bytes vs %d)", len(plain), len(r.plain))
	}
	served := r.logs.Matching(slog.LevelInfo, "streamed")
	if len(served) != 1 {
		t.Fatalf("(d) INFO stream-served records:\n%s", r.logs.Text())
	}
	for k, want := range map[string]string{"presenting_node": nodeA, "grant_node": nodeA, "job_id": "job-restore"} {
		if v, _ := logkittest.Attr(served[0], k); v != want {
			t.Errorf("(d) %s = %q, want %q", k, v, want)
		}
	}
	noPath(t, served[0])

	if strings.Contains(r.logs.Text(), cred) {
		t.Error("the credential appears in a record")
	}
	if global.Len() != 0 {
		t.Errorf("the global log was written: %q", global.String())
	}
}
