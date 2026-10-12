package sealrotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The secret store functional tests' variables (docs/testing-secret-store.md).
const (
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"
	// apiRole is the api's cert role, whose policy the canary is written under.
	apiRole = storepolicy.APIPolicy
)

// realStore is one harness store with the shipped policies, its seal outside
// the main config, and the clients and files the tests drive it with.
type realStore struct {
	store    *secretstoretest.Store
	api      *secretstore.Client // the api's client: health and the canary
	rot      *secretstore.Client // the production rotation client: a minted leaf per handshake
	apiTok   secret.Value
	files    *Files
	paths    Paths
	canaryP  secretstore.KVPath
	canary   string
	tokenTxt []string  // every token the test itself holds, for TC-830-22's scan
	leaves   *leafKeys // every rotation leaf key minted, for TC-830-22's scan
}

// startReal starts a store whose self-init creates the rasputin-secrets mount,
// the api's role and the rotation role from storepolicy's files, as the
// image's init.json does, and writes a canary.
func startReal(t *testing.T, logger *slog.Logger) *realStore {
	t.Helper()
	ctx := t.Context()
	bin := os.Getenv(binEnv)
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger,
		Now: time.Now, Rand: rand.Reader, ExternalSeal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var roles []secretstoretest.Role
	for _, name := range []string{storepolicy.APIPolicy, storepolicy.SealRotatePolicy} {
		text, err := storepolicy.Text(name)
		if err != nil {
			t.Fatal(err)
		}
		roles = append(roles, secretstoretest.Role{Name: name, Policy: name, PolicyText: text})
	}
	store, err := h.StartWith(ctx, secretstoretest.Bootstrap{Mount: storepolicy.Mount, Roles: roles})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(store.URL())
	if err != nil {
		t.Fatal(err)
	}
	apiTLS, err := store.ClientTLSFor(apiRole)
	if err != nil {
		t.Fatal(err)
	}
	api, err := secretstore.New(secretstore.Config{Addr: u, TLS: apiTLS, CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	leaves := &leafKeys{}
	rotTLS, err := secretstore.NewMintedTLSConfig(store.StoreCA().CertPEM, leaves.tee(t, MintRotationLeaf(store.StoreCA())))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := secretstore.New(secretstore.Config{Addr: u, TLS: rotTLS, CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.CloseIdleConnections)
	t.Cleanup(rot.CloseIdleConnections)
	apiTok, err := store.TokenFor(ctx, apiRole)
	if err != nil {
		t.Fatal(err)
	}
	dir := store.SealDir()
	paths := Paths{SealDir: dir, CredDir: dir, RotationCred: func(id KeyID) string { return filepath.Join(dir, RotationDirName, string(id)) }}
	files, err := NewFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	p, err := secretstore.NewKVPath(storepolicy.Mount, "apps/canary")
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	canary := "canary-" + hex.EncodeToString(raw)
	if _, err := api.Write(ctx, apiTok, p, map[string]secret.Value{"v": secret.New([]byte(canary))}, 0); err != nil {
		t.Fatal(err)
	}
	return &realStore{store: store, api: api, rot: rot, apiTok: apiTok, files: files, paths: paths,
		canaryP: p, canary: canary, tokenTxt: []string{string(apiTok.Reveal())}, leaves: leaves}
}

// restart is the harness's stand-in for restartStoreUnit: stop the store if
// it runs, start it again on whatever the seal directory now holds, and
// return without waiting, as systemctl restart returns at READY.
func (rs *realStore) restart(ctx context.Context) error {
	if rs.store.Running() {
		if err := rs.store.Stop(ctx); err != nil {
			return err
		}
	}
	return rs.store.StartNoWait(ctx)
}

// rotator is a Rotator over the real store, the real files and a fresh gate.
func (rs *realStore) rotator(t *testing.T, logger *slog.Logger) *Rotator {
	t.Helper()
	notRunning := func(context.Context, string) (bool, error) { return false, nil }
	gate, err := NewGate(rs.files, notRunning, logger)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := NewRotator(Config{Enabled: true, UnsealWait: 30 * time.Second}, Deps{
		Store: rs.api, Rotate: rs.rot, Restart: rs.restart, Files: rs.files, Gate: gate,
		Quiesce:  func(string, storestate.QuiesceReason) func() { return func() {} },
		Restores: noRestore{}, Rand: rand.Reader, KeyID: randomKeyID, Log: logger,
		JobRunning: notRunning, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rot
}

// randomKeyID is a key id from crypto/rand through the harness's own key-id
// helper; the kernel uuid file is Linux's, and the functional test runs on
// any OS.
func randomKeyID() (KeyID, error) {
	id, err := secretstoretest.SealKeyID(rand.Reader)
	if err != nil {
		return "", err
	}
	return ParseKeyID(id)
}

type noRestore struct{}

func (noRestore) Active() (string, bool) { return "", false }

// runRotation runs one rotation job on a real runner over a temporary
// ledger, and returns the job and its settle result.
func runRotation(t *testing.T, rot *Rotator) (*jobs.Job, settleResult) {
	t.Helper()
	ctx := t.Context()
	js, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	r := jobs.NewRunner(js, nil)
	r.Register(rot.Workflow())
	j, err := r.Submit(ctx, Kind, nil, "functional-test")
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	got, err := js.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := js.ListSteps(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	var res settleResult
	for _, st := range steps {
		if st.Name == "settle" && len(st.Result) > 0 {
			if err := json.Unmarshal(st.Result, &res); err != nil {
				t.Fatal(err)
			}
		}
	}
	return got, res
}

// clean asserts the tree is Clean with rotation/ empty and returns its key id.
func (rs *realStore) clean(t *testing.T) KeyID {
	t.Helper()
	tree, err := rs.files.State()
	if err != nil {
		t.Fatal(err)
	}
	if tree.Fragment.Shape != Clean || tree.Resume != Fresh {
		t.Fatalf("tree = %+v, want Clean with rotation/ empty", tree)
	}
	return tree.Fragment.Current
}

// coldRestart stops the store and starts it on the seal directory as it is,
// returning once it answers 200 unsealed.
func (rs *realStore) coldRestart(t *testing.T) {
	t.Helper()
	if err := rs.store.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := rs.store.Restart(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// readCanary asserts the canary reads back.
func (rs *realStore) readCanary(t *testing.T) {
	t.Helper()
	kv, err := rs.api.Read(t.Context(), rs.apiTok, rs.canaryP, 0)
	if err != nil {
		t.Fatalf("canary read: %v", err)
	}
	defer kv.Destroy()
	if got := string(kv.Data["v"].Reveal()); got != rs.canary {
		t.Fatal("the canary read back a different value")
	}
}

// sealKey is seal-key's bytes now, for the TC-830-22 scan.
func (rs *realStore) sealKey(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rs.paths.SealDir, SealKeyName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeKeyFile writes 32 random bytes at path and returns them.
func writeKeyFile(t *testing.T, path string) []byte {
	t.Helper()
	b := make([]byte, KeyBytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSealRotate_AgainstTheRealStore runs the rotation against the real
// pinned store through the harness, with the seal in an external fragment as
// the image has it, the shipped policies, and the production rotation client
// (geekdojo/geekdojo-brain#830; TC-830-17 to TC-830-22).
func TestSealRotate_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	log, rec := logkittest.New()
	logger := slog.New(slog.NewMultiHandler(log.Handler(), slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug})))
	rs := startReal(t, logger)
	var keys [][]byte
	keys = append(keys, rs.sealKey(t))

	t.Run("TC-830-21 the rotation token re-wraps and nothing beside it", func(t *testing.T) {
		tok, err := rs.rot.CertLogin(t.Context(), RotationRole)
		if err != nil {
			t.Fatal(err)
		}
		defer tok.Destroy()
		rs.tokenTxt = append(rs.tokenTxt, string(tok.Reveal()))
		rotTLS, err := secretstore.NewMintedTLSConfig(rs.store.StoreCA().CertPEM, rs.leaves.tee(t, MintRotationLeaf(rs.store.StoreCA())))
		if err != nil {
			t.Fatal(err)
		}
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: rotTLS}}
		defer hc.CloseIdleConnections()
		do := func(method, path, token string) (int, []byte) {
			t.Helper()
			var body io.Reader = http.NoBody
			if method != http.MethodGet {
				body = strings.NewReader("{}")
			}
			req, err := http.NewRequestWithContext(t.Context(), method, rs.store.URL()+"/v1/"+path, body)
			if err != nil {
				t.Fatal(err)
			}
			if token != "" {
				req.Header.Set("X-Vault-Token", token)
			}
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, b
		}
		tt := string(tok.Reveal())
		if code, b := do(http.MethodPost, "sys/rotate/root", tt); code != http.StatusNoContent || len(b) != 0 {
			t.Errorf("sys/rotate/root = %d with %d body bytes, want 204 and an empty body", code, len(b))
		}
		for _, p := range []struct{ method, path string }{
			{http.MethodPost, "sys/rotate/root/init"},
			{http.MethodPost, "sys/rotate/root/update"},
			{http.MethodPost, "sys/rotate/root/verify"},
			{http.MethodGet, "sys/rotate/root/backup"},
			{http.MethodPost, "sys/rotate"},
			{http.MethodGet, "sys/rotate/keyring"},
			{http.MethodGet, "sys/rotate/keyring/config"},
			{http.MethodGet, "sys/rotate/config"},
			{http.MethodPost, "sys/seal"},
			{http.MethodGet, "sys/raw/core/keyring"},
			{http.MethodGet, "sys/key-status"},
			{http.MethodGet, "sys/generate-recovery-token/attempt"},
			{http.MethodPost, "sys/capabilities-self"},
		} {
			if code, _ := do(p.method, p.path, tt); code != http.StatusForbidden {
				t.Errorf("%s %s with the rotation token = %d, want 403", p.method, p.path, code)
			}
		}
		for _, p := range []struct{ method, path string }{
			{http.MethodPut, "sys/rekey/init"},
			{http.MethodGet, "sys/generate-root/attempt"},
		} {
			if code, _ := do(p.method, p.path, ""); code != http.StatusMethodNotAllowed {
				t.Errorf("token-less %s %s = %d, want 405 at the listener", p.method, p.path, code)
			}
		}
		rs.readCanary(t)
	})

	t.Run("TC-830-17 two rotations, each surviving a cold restart under seal-key alone", func(t *testing.T) {
		for i := range 2 {
			before := rs.clean(t)
			j, res := runRotation(t, rs.rotator(t, logger))
			if j.Status != jobs.StatusSucceeded {
				t.Fatalf("rotation %d: job %s: %s", i+1, j.Status, j.Error)
			}
			after := rs.clean(t)
			if after == before || res.Outcome != "rotated" || res.KeyID != string(after) || res.PreviousKeyID != string(before) {
				t.Fatalf("rotation %d: %s -> %s, result %+v", i+1, before, after, res)
			}
			keys = append(keys, rs.sealKey(t))
			rs.coldRestart(t)
			rs.readCanary(t)
		}
	})

	t.Run("TC-830-19 cold copies before and after a rotation each open under their own key", func(t *testing.T) {
		before := snapshot(t, rs)
		j, _ := runRotation(t, rs.rotator(t, logger))
		if j.Status != jobs.StatusSucceeded {
			t.Fatalf("rotation: %s: %s", j.Status, j.Error)
		}
		keys = append(keys, rs.sealKey(t))
		after := snapshot(t, rs)
		if before.keyID == after.keyID {
			t.Fatal("the rotation did not change the key id")
		}
		for _, c := range []coldCopy{before, after} {
			restore(t, rs, c)
			if got := rs.clean(t); got != c.keyID {
				t.Fatalf("restored key id = %s, want %s", got, c.keyID)
			}
			rs.readCanary(t)
		}
	})

	t.Run("TC-830-20 a run stopped part way is finished by the next, with no new key", func(t *testing.T) {
		for _, point := range []string{"after the staged write", "after the verify write", "after the clean write"} {
			a := rs.clean(t)
			b, err := randomKeyID()
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, writeKeyFile(t, filepath.Join(rs.paths.SealDir, RotationDirName, string(b))))
			stopAt(t, rs, point, a, b)
			retries := len(rec.Matching(slog.LevelWarn, "trying once more"))
			j, res := runRotation(t, rs.rotator(t, logger))
			if j.Status != jobs.StatusSucceeded || res.Outcome != "resumed" {
				t.Fatalf("%s: job %s (%s), outcome %q, want succeeded and resumed", point, j.Status, j.Error, res.Outcome)
			}
			// F-830-14: the resume restarts under Staged before it re-wraps,
			// so verify opens first time and never takes its retry.
			if n := len(rec.Matching(slog.LevelWarn, "trying once more")); n != retries {
				t.Fatalf("%s: verify needed its retry", point)
			}
			if got := rs.clean(t); got != b {
				t.Fatalf("%s: key id after the resume = %s, want %s and no third", point, got, b)
			}
			rs.coldRestart(t)
			rs.readCanary(t)
		}
	})

	t.Run("TC-830-22 no key or token in the api log or the store's output", func(t *testing.T) {
		text := rec.Text()
		for i, k := range keys {
			for _, enc := range secretEncodings(k) {
				if strings.Contains(text, enc) {
					t.Fatalf("key %d reached the log", i)
				}
			}
		}
		for _, enc := range rs.leaves.needles(t) {
			if strings.Contains(text, enc) {
				t.Fatal("a rotation leaf key reached the log")
			}
		}
		for _, tok := range rs.tokenTxt {
			if strings.Contains(text, tok) {
				t.Fatal("a token reached the log")
			}
		}
		if m := tokenShape.FindString(text); m != "" {
			t.Fatal("a string shaped like a store token reached the log")
		}
	})

	t.Run("TC-830-18 a second rotation with no re-wrap leaves the store sealed", func(t *testing.T) {
		ac2(t, logger, rec)
	})
}

// tokenShape matches an OpenBao service or batch token.
var tokenShape = regexp.MustCompile(`\b(?:hvs|hvb|s|b)\.[A-Za-z0-9]{20,}`)

// coldCopy is the data directory, seal-key and fragment, copied with the store
// stopped.
type coldCopy struct {
	dir   string
	keyID KeyID
}

func snapshot(t *testing.T, rs *realStore) coldCopy {
	t.Helper()
	id := rs.clean(t)
	if err := rs.store.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	root := filepath.Dir(rs.paths.SealDir)
	copyTree(t, filepath.Join(root, "data"), filepath.Join(dst, "data"))
	copyFile(t, filepath.Join(rs.paths.SealDir, SealKeyName), filepath.Join(dst, SealKeyName))
	copyFile(t, filepath.Join(rs.paths.SealDir, FragmentName), filepath.Join(dst, FragmentName))
	if err := rs.store.Restart(t.Context()); err != nil {
		t.Fatal(err)
	}
	return coldCopy{dir: dst, keyID: id}
}

// restore puts c back in place of the store's data and seal files and starts
// the store on them, returning once it answers 200.
func restore(t *testing.T, rs *realStore, c coldCopy) {
	t.Helper()
	if err := rs.store.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(rs.paths.SealDir)
	if err := os.RemoveAll(filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(c.dir, "data"), filepath.Join(root, "data"))
	copyFile(t, filepath.Join(c.dir, SealKeyName), filepath.Join(rs.paths.SealDir, SealKeyName))
	copyFile(t, filepath.Join(c.dir, FragmentName), filepath.Join(rs.paths.SealDir, FragmentName))
	if err := rs.store.Restart(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// stopAt leaves the tree as a run stopped at point would, with key b already
// written to rotation/b and the store running under the Clean tree for a.
func stopAt(t *testing.T, rs *realStore, point string, a, b KeyID) {
	t.Helper()
	ctx := t.Context()
	write := func(f Fragment) {
		t.Helper()
		if err := rs.files.WriteFragment(f); err != nil {
			t.Fatal(err)
		}
	}
	open := func() {
		t.Helper()
		if err := rs.restart(ctx); err != nil {
			t.Fatal(err)
		}
		waitHealthy(t, rs.api)
	}
	write(Fragment{Shape: Staged, Current: b, Previous: a})
	if point == "after the staged write" {
		return // the store still runs under Clean, as the crash left it
	}
	open()
	tok, err := rs.rot.CertLogin(ctx, RotationRole)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Destroy()
	rs.tokenTxt = append(rs.tokenTxt, string(tok.Reveal()))
	if err := rs.rot.RotateRoot(ctx, tok); err != nil {
		t.Fatal(err)
	}
	write(Fragment{Shape: Verify, Current: b})
	if point == "after the verify write" {
		return
	}
	open()
	key, err := rs.files.ReadRotationKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.files.WriteSealKey(key); err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	write(Fragment{Shape: Clean, Current: b})
	open()
}

// waitHealthy waits for 200 on the test's ctx.
func waitHealthy(t *testing.T, c *secretstore.Client) {
	t.Helper()
	for {
		h, err := c.Health(t.Context())
		if secretstore.InactiveReason(h, err) == "" {
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal("the store never answered 200")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ac2 stages key b without a re-wrap, then key c with b as previous: the
// root key is still wrapped by a, which neither names, so the store comes up
// sealed and says which key id it does not know (AC2).
func ac2(t *testing.T, logger *slog.Logger, rec *logkittest.Recorder) {
	ctx := t.Context()
	rs := startReal(t, logger)
	dir := rs.paths.SealDir
	b, err := randomKeyID()
	if err != nil {
		t.Fatal(err)
	}
	c, err := randomKeyID()
	if err != nil {
		t.Fatal(err)
	}
	a := rs.clean(t)
	writeKeyFile(t, filepath.Join(dir, RotationDirName, string(b)))
	if err := rs.files.WriteFragment(Fragment{Shape: Staged, Current: b, Previous: a}); err != nil {
		t.Fatal(err)
	}
	if err := rs.restart(ctx); err != nil {
		t.Fatal(err)
	}
	waitHealthy(t, rs.api)
	writeKeyFile(t, filepath.Join(dir, RotationDirName, string(c)))
	frag := []byte("seal \"static\" {\n" +
		"  current_key_id  = \"" + string(c) + "\"\n" +
		"  current_key     = \"file://" + filepath.Join(dir, RotationDirName, string(c)) + "\"\n" +
		"  previous_key_id = \"" + string(b) + "\"\n" +
		"  previous_key    = \"file://" + filepath.Join(dir, RotationDirName, string(b)) + "\"\n}\n")
	if err := os.WriteFile(filepath.Join(dir, FragmentName), frag, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rs.store.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rs.store.StartNoWait(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := rs.api.Health(ctx)
		if errorsIsSealed(err) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the store never answered 503 sealed; last: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	var found bool
	for _, r := range rec.Records() {
		line, _ := logkittest.Attr(r, "line")
		if strings.Contains(line, "unknown key id") || strings.Contains(r.Message, "unknown key id") {
			found = true
		}
	}
	if !found {
		t.Error("the store's output never named an unknown key id")
	}
}

func errorsIsSealed(err error) bool { return errors.Is(err, secretstore.ErrSealed) }
