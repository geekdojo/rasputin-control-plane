package backupxfer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The ingest's one entry, ServeNode: who may present a credential on it, and
// the records each outcome writes through the injected logger.

// captureGlobalLog redirects the standard library's global logger for the
// test, so a test can assert the endpoint never writes to it.
func captureGlobalLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

// nodeEntry mounts ServeNode with a fixed key owner: the stand-in for the
// node listener's handler, which authenticated the request by owner's key.
func nodeEntry(owner string) func(*backupxfer.Ingest) http.Handler {
	return func(ing *backupxfer.Ingest) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ing.ServeNode(w, r, owner) })
	}
}

func (r *rig) mintGrant(member string) (string, backupxfer.Grant) {
	r.t.Helper()
	g := backupxfer.Grant{Generation: genID, Member: member, NodeID: nodeID, JobID: jobID, MaxBytes: 1 << 30}
	tok, err := r.ingest.Mint(g, backupxfer.CredentialTTL)
	if err != nil {
		r.t.Fatalf("Mint: %v", err)
	}
	vg, err := r.ingest.Authority().Verify(tok)
	if err != nil {
		r.t.Fatal(err)
	}
	return tok, vg
}

// wantAttrs asserts rec carries every field with the value given.
func wantAttrs(t *testing.T, rec slog.Record, want map[string]string) {
	t.Helper()
	for k, v := range want {
		got, ok := logkittest.Attr(rec, k)
		if !ok {
			t.Errorf("record %q has no %s field", rec.Message, k)
			continue
		}
		if got != v {
			t.Errorf("record %q: %s = %q, want %q", rec.Message, k, got, v)
		}
	}
}

// nothingLanded asserts no member file and no temp exist for member, and the
// ingest does not report it landed.
func (r *rig) nothingLanded(member string) {
	r.t.Helper()
	if _, err := os.Stat(r.memberPath(member)); !os.IsNotExist(err) {
		r.t.Errorf("member is on disk (stat err %v)", err)
	}
	r.noPartials()
	if _, ok := r.ingest.Landed(genID, member); ok {
		r.t.Error("Landed reports the member")
	}
}

// TC-514-05: ServeNode with no key owner fails closed, before a slot.
func TestServeNodeRefusesAnEmptyOwnerBeforeASlot(t *testing.T) {
	logger, rec := logkittest.New()
	r := newRigServing(t, 1, logger, nodeEntry(nodeID))
	tok, _ := r.mintGrant(memVW)

	// Called directly, with a body that never ends: had the entry taken the
	// one slot or read the body, this call would never return.
	body, bodyW := io.Pipe()
	t.Cleanup(func() { _ = bodyW.Close() })
	req := httptest.NewRequest(http.MethodPut, backupxfer.IngestPathPrefix+genID+"/"+memVW, body)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ingest.ServeNode(w, req, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	var p backupxfer.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Code != backupxfer.CodeCredentialInvalid {
		t.Fatalf("body = %s (%v), want code %s", w.Body.String(), err, backupxfer.CodeCredentialInvalid)
	}
	if errs := rec.AtLevel(slog.LevelError); len(errs) != 1 || !strings.Contains(errs[0].Message, "wiring fault") {
		t.Fatalf("ERROR records:\n%s", rec.Text())
	}
	r.nothingLanded(memVW)

	// The slot is free: a valid request on the node entry lands at once.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.put(ctx, tok, memVW, []byte("vaultwarden")); err != nil {
		t.Fatalf("a valid request after the refusal: %v", err)
	}
}

// TC-514-06: on the node listener, a credential issued to another node is
// refused, whoever's key presents it.
func TestServeNodeRefusesAnotherNodesCredential(t *testing.T) {
	global := captureGlobalLog(t)
	logger, rec := logkittest.New()
	const other = "e3bench-compute2"
	r := newRigServing(t, 1, logger, nodeEntry(other))
	tok, g := r.mintGrant(memVW)

	_, err := r.put(context.Background(), tok, memVW, []byte("vaultwarden"))
	refusedWith(t, err, backupxfer.CodeCredentialScope)
	r.nothingLanded(memVW)
	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 {
		t.Fatalf("WARN records = %d, want 1:\n%s", len(warns), rec.Text())
	}
	wantAttrs(t, warns[0], map[string]string{
		"grant_id": g.ID(), "job_id": jobID, "grant_node": nodeID, "presenting_node": other,
		"code": backupxfer.CodeCredentialScope,
	})
	noPathAttr(t, warns[0])
	if global.Len() != 0 {
		t.Errorf("the global log was written: %q", global.String())
	}
	if strings.Contains(rec.Text(), tok) {
		t.Error("the credential appears in a log")
	}
}

// TC-514-07: on the node listener, the credential's own node lands it.
// TC-516-02: the landing record names the presenting node and the grant's
// node, and carries no path attribute.
func TestServeNodeLandsItsOwnNodesCredential(t *testing.T) {
	logger, rec := logkittest.New()
	r := newRigServing(t, 1, logger, nodeEntry(nodeID))
	tok, _ := r.mintGrant(memVW)
	rc, err := r.put(context.Background(), tok, memVW, []byte("vaultwarden"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if digest := fileDigest(t, r.memberPath(memVW)); digest != rc.SealedDigest {
		t.Errorf("on-disk digest %s, receipt %s", digest, rc.SealedDigest)
	}
	landed := rec.Matching(slog.LevelInfo, "landed")
	if len(landed) != 1 {
		t.Fatalf("INFO landing records = %d, want 1:\n%s", len(landed), rec.Text())
	}
	wantAttrs(t, landed[0], map[string]string{
		"presenting_node": nodeID, "grant_node": nodeID, "job_id": jobID,
	})
	// TC-516-02: with one entry the record has no path to name.
	noPathAttr(t, landed[0])
}

// noPathAttr asserts rec carries no "path" attribute (TC-516-02).
func noPathAttr(t *testing.T, rec slog.Record) {
	t.Helper()
	if v, ok := logkittest.Attr(rec, "path"); ok {
		t.Errorf("record %q carries path=%q; the only entry is the node listener", rec.Message, v)
	}
}

// TC-514-30: the constructor refuses a nil logger, naming it.
func TestNewRefusesANilLogger(t *testing.T) {
	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		v := recover()
		if v == nil {
			t.Fatal("New(auth, 1, nil) did not panic")
		}
		if s, _ := v.(string); !strings.Contains(s, "logger") {
			t.Fatalf("panic %v does not name the logger", v)
		}
	}()
	backupxfer.New(auth, 1, nil)
}

// fileDigest is the sha256 of the file at path, hex.
func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("member not on disk: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
