package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Backup transfer on the node listener, over real TLS: the production
// handshake and admission (keyListener), authenticateNode on the backup
// routes, and the real ingest and restore egress behind them, driven by the
// real backupxfer HTTP client presenting a node's key.

const (
	nbGen    = "20261003T120000Z-JOB51400-full"
	nbJob    = "job-514"
	nbMember = "volumes/vaultwarden/vaultwarden-data.rasputin-archive"
)

// nodeBackupRig is a node listener with node A and node B, each with an agent
// and a collector key registered, and the backup endpoints wired.
type nodeBackupRig struct {
	t        *testing.T
	s        *Server
	it       *ingressTLS
	apiLog   *logkittest.Recorder // the server's injected logger
	xferLog  *logkittest.Recorder // the ingest's and the egress's
	ingest   *backupxfer.Ingest
	egress   *storage.RestoreEgress
	sessions *storage.RestoreSessions
	genDir   string
	certs    map[string]tls.Certificate // "n-a/agent", "n-a/collector", …
	targetPK string
	target   *ecdh.PrivateKey
}

func newNodeBackupRig(t *testing.T) *nodeBackupRig {
	t.Helper()
	ctx := context.Background()
	s, inv, it := keyListener(t, "n-a", "n-b")
	apiLogger, apiLog := logkittest.New()
	s.log = apiLogger
	xferLogger, xferLog := logkittest.New()

	auth, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	ing := backupxfer.New(auth, 1, xferLogger)
	s.SetBackupIngest(ing)
	sessions := storage.NewRestoreSessions()
	eg := storage.NewRestoreEgress(auth, sessions, xferLogger)
	s.SetAppRestore(&storage.RestoreAppConfig{}, eg)
	genDir, err := ing.Open(filepath.Join(t.TempDir(), "mnt", proto.BackupGenerationsDir), nbGen, nbJob)
	if err != nil {
		t.Fatal(err)
	}

	r := &nodeBackupRig{t: t, s: s, it: it, apiLog: apiLog, xferLog: xferLog, ingest: ing, egress: eg,
		sessions: sessions, genDir: genDir, certs: map[string]tls.Certificate{}}
	for _, node := range []string{"n-a", "n-b"} {
		keys := proto.NodeKeys{}
		for _, p := range []proto.NodeKeyPurpose{proto.NodeKeyAgent, proto.NodeKeyCollector} {
			cert, hash := selfSignedClient(t, node)
			r.certs[node+"/"+string(p)] = cert
			keys[p] = hash
		}
		if _, err := inv.SetNodeKeys(ctx, node, keys); err != nil {
			t.Fatal(err)
		}
	}
	r.target, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.targetPK = base64.RawURLEncoding.EncodeToString(r.target.PublicKey().Bytes())
	return r
}

// tlsAs is the client config presenting cert, trusting the listener.
func (r *nodeBackupRig) tlsAs(cert tls.Certificate) *tls.Config {
	return r.it.keyClientTLS(cert)
}

func (r *nodeBackupRig) mint(node string, use string) string {
	r.t.Helper()
	g := backupxfer.Grant{Generation: nbGen, Member: nbMember, NodeID: node, JobID: nbJob, MaxBytes: 1 << 20, Use: use}
	var tok string
	var err error
	if use == backupxfer.UseRestore {
		tok, err = r.egress.Mint(g, time.Minute)
	} else {
		tok, err = r.ingest.Mint(g, time.Minute)
	}
	if err != nil {
		r.t.Fatalf("Mint: %v", err)
	}
	return tok
}

// put uploads a sealed member through the real HTTP transport.
func (r *nodeBackupRig) put(cfg *tls.Config, cred string) (*backupxfer.Receipt, error) {
	r.t.Helper()
	dest, err := backupxfer.IngestDestination(r.it.srv.URL)
	if err != nil {
		r.t.Fatal(err)
	}
	plain := []byte(strings.Repeat("vault ", 1000))
	sum := sha256.Sum256(plain)
	stream := backupxfer.NewSealedStream(bytes.NewReader(plain), r.targetPK, "key-1", proto.BackupScopeFull)
	tr := backupxfer.NewHTTPTransport(backupxfer.HTTPOptions{TLSConfig: cfg, AcceptWait: 5 * time.Second})
	return tr.Put(context.Background(), backupxfer.PutRequest{
		Destination: dest, Generation: nbGen, Member: nbMember, Credential: cred,
		PlaintextDigest: hex.EncodeToString(sum[:]), PlaintextBytes: uint64(len(plain)),
		Body: stream, Sealed: stream.Sealed,
	})
}

// raw makes one request presenting cfg and returns the status and the coded
// error body.
func (r *nodeBackupRig) raw(cfg *tls.Config, method, prefix, cred string) (int, codedError) {
	r.t.Helper()
	req, err := http.NewRequest(method, r.it.srv.URL+prefix+nbGen+"/"+nbMember, strings.NewReader("x"))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := c.Do(req)
	if err != nil {
		r.t.Fatalf("%s %s: %v", method, prefix, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body codedError
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &body)
	return resp.StatusCode, body
}

// nothingLanded asserts the member is not on disk and not recorded.
func (r *nodeBackupRig) nothingLanded() {
	r.t.Helper()
	if _, err := os.Stat(filepath.Join(r.genDir, filepath.FromSlash(nbMember))); !errors.Is(err, os.ErrNotExist) {
		r.t.Errorf("the member is on disk (stat: %v)", err)
	}
	if _, ok := r.ingest.Landed(nbGen, nbMember); ok {
		r.t.Error("the ingest records the member landed")
	}
}

// refusalRecord finds the server's WARN record for correlation id cid.
func (r *nodeBackupRig) refusalRecord(cid string) slog.Record {
	r.t.Helper()
	for _, rec := range r.apiLog.AtLevel(slog.LevelWarn) {
		if v, _ := logkittest.Attr(rec, "correlation_id"); v == cid && cid != "" {
			return rec
		}
	}
	r.t.Fatalf("no WARN record with correlation_id %q:\n%s", cid, r.apiLog.Text())
	return slog.Record{}
}

func wantFields(t *testing.T, rec slog.Record, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got, ok := logkittest.Attr(rec, k); !ok || got != v {
			t.Errorf("record %q: %s = %q (present %v), want %q", rec.Message, k, got, ok, v)
		}
	}
}

// TC-514-15: a member uploaded by its node's agent key lands, and its record
// names the presenting node and no path (TC-516-02).
func TestNodeBackup_KeyedUploadLands(t *testing.T) {
	r := newNodeBackupRig(t)
	rc, err := r.put(r.tlsAs(r.certs["n-a/agent"]), r.mint("n-a", ""))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(r.genDir, filepath.FromSlash(nbMember)))
	if err != nil {
		t.Fatalf("the member is not on disk: %v", err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != rc.SealedDigest {
		t.Errorf("on-disk digest differs from the receipt's %s", rc.SealedDigest)
	}
	landed := r.xferLog.Matching(slog.LevelInfo, "landed")
	if len(landed) != 1 {
		t.Fatalf("landing records:\n%s", r.xferLog.Text())
	}
	wantFields(t, landed[0], map[string]string{"presenting_node": "n-a", "grant_node": "n-a"})
	if v, ok := logkittest.Attr(landed[0], "path"); ok {
		t.Errorf("the landing record carries path=%q", v)
	}
}

// TC-514-16: the node's collector key, registered and admitted, cannot move
// its backups.
func TestNodeBackup_CollectorKeyIsRefused(t *testing.T) {
	r := newNodeBackupRig(t)
	code, body := r.raw(r.tlsAs(r.certs["n-a/collector"]), http.MethodPut, backupxfer.IngestPathPrefix, r.mint("n-a", ""))
	if code != http.StatusForbidden || !strings.Contains(body.Error, "a registered agent key is required") || body.Code == "" || body.CorrelationID == "" {
		t.Fatalf("got %d %+v", code, body)
	}
	r.nothingLanded()
	rec := r.refusalRecord(body.CorrelationID)
	wantFields(t, rec, map[string]string{"node_id": "n-a", "purpose": string(proto.NodeKeyCollector), "route": "PUT " + backupxfer.IngestPathPrefix})
}

// TC-514-18: node B's agent key cannot spend node A's credential.
func TestNodeBackup_AnotherNodesKeyIsRefused(t *testing.T) {
	r := newNodeBackupRig(t)
	_, err := r.put(r.tlsAs(r.certs["n-b/agent"]), r.mint("n-a", ""))
	var re *backupxfer.RefusedError
	if !errors.As(err, &re) || re.Status != http.StatusForbidden || re.Problem.Code != backupxfer.CodeCredentialScope {
		t.Fatalf("err = %v, want 403 %s", err, backupxfer.CodeCredentialScope)
	}
	r.nothingLanded()
}

// TC-514-19: the restore stream fetched by its node's agent key, and refused
// to another node's key and to the node's collector key.
func TestNodeBackup_KeyedRestoreFetch(t *testing.T) {
	r := newNodeBackupRig(t)
	plain := []byte(strings.Repeat("TAR BYTES ", 4000))
	var sealed bytes.Buffer
	if _, err := backupxfer.Seal(&sealed, bytes.NewReader(plain), r.targetPK, "key-1", proto.BackupScopeFull); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(t.TempDir(), "restore-mnt")
	p := filepath.Join(mount, proto.BackupGenerationsDir, nbGen, filepath.FromSlash(nbMember))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sealedSum, plainSum := sha256.Sum256(sealed.Bytes()), sha256.Sum256(plain)
	id, err := r.sessions.Open(r.target.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.sessions.Bind(id, nbJob); err != nil {
		t.Fatal(err)
	}
	if err := r.sessions.Arm(id, mount, "part", nbGen, "n-a", []storage.RestoreVolumePlan{{
		Member: nbMember, SealedSHA256: hex.EncodeToString(sealedSum[:]), SealedBytes: uint64(sealed.Len()),
		SHA256: hex.EncodeToString(plainSum[:]), SizeBytes: uint64(len(plain)),
	}}); err != nil {
		t.Fatal(err)
	}
	cred := r.mint("n-a", backupxfer.UseRestore)
	source, err := backupxfer.EgressDestination(r.it.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	get := func(cert tls.Certificate) ([]byte, error) {
		tr := backupxfer.NewHTTPTransport(backupxfer.HTTPOptions{TLSConfig: r.tlsAs(cert)})
		st, err := tr.Get(context.Background(), backupxfer.GetRequest{Source: source, Generation: nbGen, Member: nbMember, Credential: cred})
		if err != nil {
			return nil, err
		}
		defer func() { _ = st.Body.Close() }()
		return io.ReadAll(st.Body)
	}

	got, err := get(r.certs["n-a/agent"])
	if err != nil {
		t.Fatalf("A's agent key: %v", err)
	}
	if sum := sha256.Sum256(got); len(got) != len(plain) || sum != plainSum {
		t.Fatalf("the stream is %d bytes with another digest; the manifest says %d", len(got), len(plain))
	}
	_, err = get(r.certs["n-b/agent"])
	var re *backupxfer.RefusedError
	if !errors.As(err, &re) || re.Status != http.StatusForbidden || re.Problem.Code != backupxfer.CodeCredentialScope {
		t.Fatalf("B's agent key: %v, want 403 %s", err, backupxfer.CodeCredentialScope)
	}
	_, err = get(r.certs["n-a/collector"])
	if !errors.As(err, &re) || re.Status != http.StatusForbidden {
		t.Fatalf("A's collector key: %v, want 403", err)
	}
}

// TC-516-11: with the mesh-chain allowance gone, the purpose check is the
// whole route rule: the agent key cannot push the collector's metrics or
// logs, and the collector key cannot move a backup in either direction. Each
// is a 403 node_key_wrong_purpose, and nothing lands or streams.
func TestNodeListener_EveryRouteChecksTheKeyPurpose(t *testing.T) {
	r := newNodeBackupRig(t)
	for _, c := range []struct {
		key, method, path, cred string
	}{
		{"n-a/agent", http.MethodPost, "/api/obs/ingest", ""},
		{"n-a/agent", http.MethodPost, "/api/obs/logs/ingest", ""},
		{"n-a/collector", http.MethodPut, backupxfer.IngestPathPrefix + nbGen + "/" + nbMember, r.mint("n-a", "")},
		{"n-a/collector", http.MethodGet, backupxfer.EgressPathPrefix + nbGen + "/" + nbMember, "rbx1.unused.unused"},
	} {
		req, err := http.NewRequest(c.method, r.it.srv.URL+c.path, strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		if c.cred != "" {
			req.Header.Set("Authorization", "Bearer "+c.cred)
		}
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: r.tlsAs(r.certs[c.key])}}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s %s: %v", c.key, c.method, c.path, err)
		}
		var body codedError
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || body.Code != codeNodeKeyPurpose {
			t.Errorf("%s %s %s = %d %q, want 403 %s", c.key, c.method, c.path, resp.StatusCode, body.Code, codeNodeKeyPurpose)
		}
	}
	r.nothingLanded()
	if served := r.xferLog.Matching(slog.LevelInfo, "streamed"); len(served) != 0 {
		t.Error("something was streamed")
	}
}

// TC-514-20: the backup routes are in the node listener's enumeration, which
// TestObsIngestRoutesRequireClientCert walks for its 503 and 401.
func TestNodeListenerRoutesIncludeBackupTransfer(t *testing.T) {
	patterns := (&Server{}).obsIngestRoutes().Patterns()
	for _, want := range []string{"PUT " + backupxfer.IngestPathPrefix, "GET " + backupxfer.EgressPathPrefix} {
		if !slices.Contains(patterns, want) {
			t.Errorf("node-listener routes %v lack %s", patterns, want)
		}
	}
}

// TC-514-29: a collector route refusing an agent key writes one WARN record
// through the server's injected logger, and nothing to the global log.
func TestNodeListener_CollectorRouteRefusalIsAStructuredRecord(t *testing.T) {
	var global bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&global)
	t.Cleanup(func() { log.SetOutput(prev) })

	r := newNodeBackupRig(t)
	req, err := http.NewRequest(http.MethodPost, r.it.srv.URL+"/api/obs/ingest", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: r.tlsAs(r.certs["n-a/agent"])}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body codedError
	_ = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || body.Error != "obs ingest: this key is not the node's collector key" {
		t.Fatalf("got %d %+v", resp.StatusCode, body)
	}
	if warns := r.apiLog.AtLevel(slog.LevelWarn); len(warns) != 1 {
		t.Fatalf("WARN records:\n%s", r.apiLog.Text())
	}
	rec := r.refusalRecord(body.CorrelationID)
	wantFields(t, rec, map[string]string{"route": obsIngestPattern, "node_id": "n-a", "purpose": string(proto.NodeKeyAgent)})
	if global.Len() != 0 {
		t.Errorf("the global log was written: %q", global.String())
	}
}

// An api with no backup endpoint wired answers the keyed routes 503, after
// authenticating the node, as the public routes do: a coded refusal with a
// correlation id, and a WARN record under that id (F-514-11).
func TestNodeBackup_UnwiredEndpointsAnswer503(t *testing.T) {
	r := newNodeBackupRig(t)
	r.s.backupIngest, r.s.restoreEgress = nil, nil
	cfg := r.tlsAs(r.certs["n-a/agent"])
	for _, c := range []struct{ method, prefix string }{
		{http.MethodPut, backupxfer.IngestPathPrefix},
		{http.MethodGet, backupxfer.EgressPathPrefix},
	} {
		code, body := r.raw(cfg, c.method, c.prefix, "rbx1.unused.unused")
		if code != http.StatusServiceUnavailable || body.Code != codeBackupTransferUnconfigured || body.CorrelationID == "" {
			t.Fatalf("%s %s = %d %+v, want 503 %s with a correlation id", c.method, c.prefix, code, body, codeBackupTransferUnconfigured)
		}
		rec := r.refusalRecord(body.CorrelationID)
		wantFields(t, rec, map[string]string{
			"route":   c.method + " " + c.prefix,
			"code":    codeBackupTransferUnconfigured,
			"node_id": "n-a",
		})
	}
}
