package secrets_test

import (
	"context"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeStore is a secrets.Store that records every call and answers from its
// fields.
type fakeStore struct {
	mu      sync.Mutex
	calls   []string
	paths   []secretstore.KVPath
	cas     []int
	written []map[string]secret.Value

	// read answers Read; nil returns readErr.
	read    func() secretstore.KV
	readErr error
	// current is what Versions reports; versionsErr fails it.
	current     int
	versionsErr error
	// writeErr fails Write; otherwise it returns cas+1.
	writeErr  error
	deleteErr error
}

func (f *fakeStore) note(op string, p secretstore.KVPath) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op)
	f.paths = append(f.paths, p)
}

func (f *fakeStore) Read(_ context.Context, p secretstore.KVPath, _ int) (secretstore.KV, error) {
	f.note("read", p)
	if f.read == nil {
		return secretstore.KV{}, f.readErr
	}
	return f.read(), nil
}

func (f *fakeStore) Write(_ context.Context, p secretstore.KVPath, data map[string]secret.Value, cas int) (int, error) {
	f.note("write", p)
	f.mu.Lock()
	f.cas = append(f.cas, cas)
	f.written = append(f.written, data)
	f.mu.Unlock()
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return cas + 1, nil
}

func (f *fakeStore) Versions(_ context.Context, p secretstore.KVPath) (secretstore.Metadata, error) {
	f.note("versions", p)
	if f.versionsErr != nil {
		return secretstore.Metadata{}, f.versionsErr
	}
	return secretstore.Metadata{CurrentVersion: f.current}, nil
}

func (f *fakeStore) Delete(_ context.Context, p secretstore.KVPath) error {
	f.note("delete", p)
	return f.deleteErr
}

func (f *fakeStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeRepo is a secrets.Repository that records every call.
type fakeRepo struct {
	mu    sync.Mutex
	calls []string
	// written is the bytes of each value Write was given, in order.
	written []string
	// inner, when set, answers each call.
	inner secrets.Repository
}

func (f *fakeRepo) note(op string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op)
}

// callCount is the number of repository calls; the switch's entries in the
// shared log are not repository calls.
func (f *fakeRepo) callCount() int {
	return len(f.repoCalls())
}

func (f *fakeRepo) Get(ctx context.Context, r secrets.Ref) (secrets.Secret, error) {
	f.note("get")
	return f.inner.Get(ctx, r)
}

func (f *fakeRepo) Write(ctx context.Context, r secrets.Ref, v secret.Value, cas int) (int, error) {
	f.note("write")
	f.mu.Lock()
	f.written = append(f.written, string(v.Reveal()))
	f.mu.Unlock()
	return f.inner.Write(ctx, r, v, cas)
}

func (f *fakeRepo) CurrentVersion(ctx context.Context, r secrets.Ref) (int, error) {
	f.note("current")
	return f.inner.CurrentVersion(ctx, r)
}

func (f *fakeRepo) Delete(ctx context.Context, r secrets.Ref) error {
	f.note("delete")
	return f.inner.Delete(ctx, r)
}

// fakeSwitch is a secrets.Switch that records each MarkSwitched in the log
// it shares with a fakeRepo, so a test sees the marker's place among the
// repository calls, and fails with err when it is set.
type fakeSwitch struct {
	log *fakeRepo
	err error
}

func (f *fakeSwitch) MarkSwitched(context.Context) error {
	f.log.note("mark")
	return f.err
}

// marks is how many times the switch was set.
func (f *fakeRepo) marks() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == "mark" {
			n++
		}
	}
	return n
}

// repoCalls is the log without the switch's entries.
func (f *fakeRepo) repoCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c != "mark" {
			out = append(out, c)
		}
	}
	return out
}

// fakeApps is a secrets.AppTargets over a map of app ID to target node.
type fakeApps struct {
	nodes map[string]string
	err   error
}

func (f fakeApps) TargetNode(_ context.Context, appID string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	n, ok := f.nodes[appID]
	return n, ok, nil
}

func appRef(t *testing.T, appID, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.AppSecret(appID, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func deviceRef(t *testing.T, kind, name string) secrets.Ref {
	t.Helper()
	r, err := secrets.DeviceSecret(kind, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func val(s string) secret.Value { return secret.New([]byte(s)) }
