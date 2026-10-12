package sealrotate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The two key ids every unit test uses: A is the key on disk, B the new one.
const (
	idA KeyID = "rasputin-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	idB KeyID = "rasputin-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

// keyA and keyB are the two keys' bytes.
var (
	keyA = bytes.Repeat([]byte{0xA1}, KeyBytes)
	keyB = bytes.Repeat([]byte{0xB2}, KeyBytes)
)

// testPaths is the production layout with the seal directory under dir.
func testPaths(dir string) Paths {
	p := ProductionPaths()
	p.SealDir = dir
	return p
}

// seal is a seal directory under construction.
type seal struct {
	t     *testing.T
	dir   string
	paths Paths
	files *Files
}

// newSeal makes an empty seal directory with rotation/.
func newSeal(t *testing.T) *seal {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "openbao-seal")
	if err := os.MkdirAll(filepath.Join(dir, RotationDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	p := testPaths(dir)
	f, err := NewFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	return &seal{t: t, dir: dir, paths: p, files: f}
}

// clean writes #803's tree for key A: seal-key and the Clean fragment.
func (s *seal) clean() *seal {
	s.write(SealKeyName, keyA)
	s.fragment(Fragment{Shape: Clean, Current: idA})
	return s
}

func (s *seal) write(rel string, b []byte) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, rel), b, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

func (s *seal) fragment(f Fragment) {
	s.t.Helper()
	b, err := f.render(s.paths)
	if err != nil {
		s.t.Fatal(err)
	}
	s.write(FragmentName, b)
}

func (s *seal) rot(id KeyID, b []byte) { s.write(filepath.Join(RotationDirName, string(id)), b) }

func (s *seal) read(rel string) []byte {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dir, rel))
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// rotationNames lists rotation/.
func (s *seal) rotationNames() []string {
	s.t.Helper()
	es, err := os.ReadDir(filepath.Join(s.dir, RotationDirName))
	if err != nil {
		s.t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// hash is every file's path, mode and bytes under the seal directory: equal
// hashes mean nothing was changed.
func (s *seal) hash() string {
	s.t.Helper()
	h := sha256.New()
	var paths []string
	err := filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		s.t.Fatal(err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil {
			s.t.Fatal(err)
		}
		fmt.Fprintf(h, "%s %v\n", strings.TrimPrefix(p, s.dir), fi.Mode())
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil && !errors.Is(err, fs.ErrPermission) {
				s.t.Fatal(err)
			}
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// shape reads the tree's fragment shape and current id.
func (s *seal) state() Tree {
	s.t.Helper()
	tree, err := s.files.State()
	if err != nil {
		s.t.Fatalf("State: %v", err)
	}
	return tree
}

// recorder is the shared call log the fakes append to, so a test can assert
// the order of store, file and unit calls.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *recorder) count(s string) int {
	n := 0
	for _, c := range r.list() {
		if c == s {
			n++
		}
	}
	return n
}

// index is the position of the first call equal to s after from, or -1.
func (r *recorder) index(s string, from int) int {
	l := r.list()
	for i := from; i < len(l); i++ {
		if l[i] == s {
			return i
		}
	}
	return -1
}

// fakeStore answers Health from up: 200 when true, 503 sealed when false.
// A restart sets up from next, a queue of answers for each restart in turn
// (empty: the store comes up).
type fakeStore struct {
	rec  *recorder
	mu   sync.Mutex
	up   bool
	err  error // when set, every answer is this error
	next []bool
}

func (f *fakeStore) Health(context.Context) (secretstore.Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec.add("health")
	if f.err != nil {
		return secretstore.Health{}, f.err
	}
	if !f.up {
		return secretstore.Health{}, &secretstore.Error{Op: "health", Status: 503, Kind: secretstore.ErrSealed}
	}
	return secretstore.Health{Initialized: true}, nil
}

func (f *fakeStore) restarted() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up = true
	if len(f.next) > 0 {
		f.up, f.next = f.next[0], f.next[1:]
	}
}

// fakeRotate is the rotation role's client.
type fakeRotate struct {
	rec       *recorder
	token     string
	loginErr  error
	rewrapErr error
	logins    int
	tokens    []secret.Value
}

func (f *fakeRotate) CertLogin(context.Context, string) (secret.Value, error) {
	f.rec.add("login")
	f.logins++
	if f.loginErr != nil {
		return secret.Value{}, f.loginErr
	}
	v := secret.New([]byte(f.token))
	f.tokens = append(f.tokens, v)
	return v, nil
}

func (f *fakeRotate) RotateRoot(_ context.Context, tok secret.Value) error {
	if string(tok.Reveal()) != f.token {
		f.rec.add("rotate_root with the wrong token")
	} else {
		f.rec.add("rotate_root")
	}
	return f.rewrapErr
}

// faultFiles is the real Files with a hook before each write, and every call
// recorded by name. A hook returning an error fails that call.
type faultFiles struct {
	*Files
	rec    *recorder
	fail   func(call string) error
	values []secret.Value // every key handed to a write, for the Len check
}

func (f *faultFiles) hook(call string) error {
	f.rec.add(call)
	if f.fail != nil {
		return f.fail(call)
	}
	return nil
}

func (f *faultFiles) State() (Tree, error) { return f.Files.State() }

func (f *faultFiles) WriteRotationKey(id KeyID, key secret.Value) error {
	f.values = append(f.values, key)
	if err := f.hook("write rotation/" + string(id)); err != nil {
		return err
	}
	return f.Files.WriteRotationKey(id, key)
}

func (f *faultFiles) WriteSealKey(key secret.Value) error {
	f.values = append(f.values, key)
	if err := f.hook("write seal-key"); err != nil {
		return err
	}
	return f.Files.WriteSealKey(key)
}

func (f *faultFiles) ReadRotationKey(id KeyID) (secret.Value, error) {
	if err := f.hook("read rotation/" + string(id)); err != nil {
		return secret.Value{}, err
	}
	return f.Files.ReadRotationKey(id)
}

func (f *faultFiles) WriteFragment(fr Fragment) error {
	if err := f.hook("fragment " + fr.Shape.String()); err != nil {
		return err
	}
	return f.Files.WriteFragment(fr)
}

func (f *faultFiles) RemoveRotation() error {
	if err := f.hook("remove rotation"); err != nil {
		return err
	}
	return f.Files.RemoveRotation()
}

// fakeRand fills each read with b's bytes and keeps every buffer it filled,
// so a test can check the caller zeroed it.
type fakeRand struct {
	b      []byte
	short  bool
	filled [][]byte
}

func (r *fakeRand) Read(p []byte) (int, error) {
	r.filled = append(r.filled, p)
	if r.short {
		n := copy(p, r.b[:len(r.b)/2])
		return n, io.ErrUnexpectedEOF
	}
	return copy(p, r.b), nil
}

// quiesceRec counts quiesce holds and their releases.
type quiesceRec struct {
	mu       sync.Mutex
	holds    int
	releases int
	reasons  []storestate.QuiesceReason
}

func (q *quiesceRec) quiesce(_ string, reason storestate.QuiesceReason) func() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.holds++
	q.reasons = append(q.reasons, reason)
	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			defer q.mu.Unlock()
			q.releases++
		})
	}
}

type restores struct{ active bool }

func (r restores) Active() (string, bool) { return "job-restore", r.active }

// rig is a Rotator over a seal tree and fakes.
type rig struct {
	seal     *seal
	rec      *recorder
	store    *fakeStore
	rotate   *fakeRotate
	files    *faultFiles
	gate     *Gate
	quiesce  *quiesceRec
	rand     *fakeRand
	keyIDs   int
	keyIDErr error
	restarts int
	restores restores
	log      *logkittest.Recorder
	rot      *Rotator
	enabled  bool
}

func newRig(t *testing.T, s *seal) *rig {
	t.Helper()
	r := &recorder{}
	g := &rig{
		seal: s, rec: r, enabled: true,
		store:   &fakeStore{rec: r, up: true},
		rotate:  &fakeRotate{rec: r, token: "hvs.FAKE-ROTATION-TOKEN-0123456789"},
		files:   &faultFiles{Files: s.files, rec: r},
		quiesce: &quiesceRec{},
		rand:    &fakeRand{b: keyB},
	}
	return g
}

// build makes the Rotator; call it after setting the rig's fields.
func (g *rig) build(t *testing.T) *rig {
	t.Helper()
	logger, recd := logkittest.New()
	g.log = recd
	notRunning := func(context.Context, string) (bool, error) { return false, nil }
	gate, err := NewGate(g.files, notRunning, logger)
	if err != nil {
		t.Fatal(err)
	}
	g.gate = gate
	rot, err := NewRotator(Config{Enabled: g.enabled, UnsealWait: 200 * time.Millisecond}, Deps{
		Store: g.store, Rotate: g.rotate, Files: g.files, Gate: gate,
		Restart: func(context.Context) error {
			g.rec.add("restart")
			g.restarts++
			g.store.restarted()
			return nil
		},
		Quiesce:  g.quiesce.quiesce,
		Restores: g.restores,
		Rand:     g.rand,
		KeyID: func() (KeyID, error) {
			g.rec.add("key id")
			g.keyIDs++
			if g.keyIDErr != nil {
				return "", g.keyIDErr
			}
			return idB, nil
		},
		Log:        logger,
		JobRunning: notRunning,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.rot = rot
	return g
}

// result is one finished job.
type result struct {
	job    *jobs.Job
	steps  []*jobs.JobStep
	events []*jobs.JobEvent
	js     *jobs.Store
}

// failedStep is the name of the step that failed, or "".
func (r result) failedStep() string {
	for _, s := range r.steps {
		if s.Status == jobs.StepFailed {
			return s.Name
		}
	}
	return ""
}

// stepResult is the named step's result JSON.
func (r result) stepResult(name string) string {
	for _, s := range r.steps {
		if s.Name == name {
			return string(s.Result)
		}
	}
	return ""
}

// run runs one rotation job on a real runner over a temporary ledger.
func (g *rig) run(t *testing.T) result {
	t.Helper()
	ctx := t.Context()
	js, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	runner := jobs.NewRunner(js, nil)
	runner.Register(g.rot.Workflow())
	j, err := runner.Submit(ctx, Kind, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	job, err := js.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := js.ListSteps(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := js.ListEvents(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	return result{job: job, steps: steps, events: evs, js: js}
}

// alertsOver is an alerts.Service over the job ledger, with empty inventory,
// apps and setup stores (storeaudit's helper).
func alertsOver(t *testing.T, js *jobs.Store) *alerts.Service {
	t.Helper()
	ctx := t.Context()
	dir := t.TempDir()
	inv, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	as, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Close() })
	ss, err := setup.OpenStore(ctx, filepath.Join(dir, "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	no := func(context.Context) (bool, error) { return false, nil }
	return alerts.New(inv, js, as, setup.NewService(ss, setup.Probes{HasUsers: no, ConsoleRootSet: no}, "", "", ""), nil, nil, true)
}

// jobFailedAlert is the job-failed alert for jobID, if the list has one.
func jobFailedAlert(t *testing.T, js *jobs.Store, jobID string) (proto.Alert, bool) {
	t.Helper()
	list, err := alertsOver(t, js).List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		if a.ID == "job-failed:"+jobID {
			return a, true
		}
	}
	return proto.Alert{}, false
}

// isSentence reports whether s starts with a capital and ends with a full
// stop.
func isSentence(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z' && strings.HasSuffix(s, ".")
}

// attr is a record's field, failing the test when it is absent.
func attr(t *testing.T, r slog.Record, key string) string {
	t.Helper()
	v, ok := logkittest.Attr(r, key)
	if !ok {
		t.Fatalf("record %q has no %s field", r.Message, key)
	}
	return v
}

// secretEncodings is every form a secret's bytes could take on a text
// surface: raw, hex, base64 padded and unpadded.
func secretEncodings(b []byte) []string {
	return []string{string(b), hexOf(b), b64(b), b64raw(b)}
}

// leafKeys tees a mint: every leaf key it mints is recorded as PKCS#8 DER,
// so a surface scan can look for the leaf key the client really presented
// (TC-830-15). The mint itself is the production one, untouched.
type leafKeys struct {
	mu   sync.Mutex
	ders [][]byte
}

func (l *leafKeys) tee(t *testing.T, mint func() (*tls.Certificate, error)) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) {
		c, err := mint()
		if err != nil {
			return c, err
		}
		der, merr := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
		if merr != nil {
			t.Errorf("leaf key: %v", merr)
			return c, err
		}
		l.mu.Lock()
		l.ders = append(l.ders, der)
		l.mu.Unlock()
		return c, err
	}
}

// needles is every recorded leaf key in each encoding, plus the first line
// of its PEM body. It fails the test when no leaf was minted, so a scan over
// it is never vacuous.
func (l *leafKeys) needles(t *testing.T) []string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ders) == 0 {
		t.Fatal("no rotation leaf was minted, so the scan would prove nothing")
	}
	var out []string
	for _, der := range l.ders {
		out = append(out, secretEncodings(der)...)
		out = append(out, b64(der)[:64])
	}
	return out
}
