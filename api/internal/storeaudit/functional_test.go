package storeaudit

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

const (
	// binEnv and switchEnv are the secret store functional tests' variables
	// (docs/testing-secret-store.md).
	binEnv    = "RASPUTIN_SECRETSTORE_BIN"
	switchEnv = "RASPUTIN_SECRETSTORE_FUNCTIONAL"

	// funcRotateAt is small, so a few hundred audited writes rotate the file.
	funcRotateAt = 64 << 10
	// writePrefix is the KV path the writer writes under.
	writePrefix = "rotate/w-"
)

// kvWriter writes KV secrets continuously through the real client, each to
// a new path, and counts what the store accepted. progress gets a value
// after each write, so the test waits on writes, not on a clock.
type kvWriter struct {
	client   *secretstore.Client
	token    secret.Value
	progress chan struct{}

	mu     sync.Mutex
	n      int
	errs   []error
	values []string
}

func (w *kvWriter) run(ctx context.Context, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		w.mu.Lock()
		n := w.n
		w.mu.Unlock()
		p, err := secretstore.NewKVPath(secretstoretest.KVMount, fmt.Sprintf("%s%d", writePrefix, n))
		if err != nil {
			w.fail(err)
			return
		}
		raw := make([]byte, 12)
		_, _ = rand.Read(raw)
		val := "kvvalue-" + hex.EncodeToString(raw)
		if _, err := w.client.Write(ctx, w.token, p, map[string]secret.Value{"v": secret.New([]byte(val))}, 0); err != nil {
			w.fail(err)
			return
		}
		w.mu.Lock()
		w.n++
		w.values = append(w.values, val)
		w.mu.Unlock()
		select {
		case w.progress <- struct{}{}:
		default:
		}
	}
}

func (w *kvWriter) fail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.errs = append(w.errs, err)
}

func (w *kvWriter) snapshot() (int, []error, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n, slices.Clone(w.errs), slices.Clone(w.values)
}

// responseCounts counts the audit `response` entries for the writer's paths,
// per path, across the live file and every copy in dir.
func responseCounts(t *testing.T, dir string) map[string]int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range ents {
		if e.Name() != LiveName && !copyName.MatchString(e.Name()) {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
		for sc.Scan() {
			var entry struct {
				Type    string `json:"type"`
				Request struct {
					Path string `json:"path"`
				} `json:"request"`
			}
			if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
				t.Fatalf("%s: an audit line is not JSON: %v", e.Name(), err)
			}
			if entry.Type == "response" && strings.HasPrefix(entry.Request.Path, secretstoretest.KVMount+"/data/"+writePrefix) {
				out[entry.Request.Path]++
			}
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
		_ = fh.Close()
	}
	return out
}

// assertNoLineLost: every write the store accepted with an index in
// [from, to) has exactly one audit response entry. A range, because the prune
// step removes the copies holding the earliest writes.
func assertNoLineLost(t *testing.T, dir string, from, to int) {
	t.Helper()
	counts := responseCounts(t, dir)
	total := 0
	for i := from; i < to; i++ {
		p := fmt.Sprintf("%s/data/%s%d", secretstoretest.KVMount, writePrefix, i)
		if counts[p] != 1 {
			t.Errorf("%s has %d audit response entries, want 1", p, counts[p])
		}
		total += counts[p]
	}
	if total != to-from {
		t.Errorf("%d audit response entries for writes %d to %d, want %d (one per accepted write)", total, from, to-1, to-from)
	}
	t.Logf("audit: writes %d to %d, %d response entries across the live file and the copies", from, to-1, total)
}

func stepLogs(t *testing.T, evs []*jobs.JobEvent) []proto.LogEventData {
	t.Helper()
	var out []proto.LogEventData
	for _, e := range evs {
		if e.Type != string(proto.JobLog) {
			continue
		}
		var d proto.LogEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// TestStoreAudit_RotateUnderLoad is the F1.4 functional test for the audit
// rotation (geekdojo/geekdojo-brain#799): the real pinned store with a file
// audit device, the real jobs.Runner on a temporary ledger with in-process
// NATS, and the harness's SIGHUP as the reopen. TC-799-29 to TC-799-32.
func TestStoreAudit_RotateUnderLoad(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	ctx := t.Context()

	log, rec := logkittest.New()
	text := slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(slog.NewMultiHandler(log.Handler(), text))
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader, Audit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := h.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	dir := filepath.Dir(store.AuditPath())
	if filepath.Base(store.AuditPath()) != LiveName {
		t.Fatalf("AuditPath = %s, want a file named %s", store.AuditPath(), LiveName)
	}
	token, err := store.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tokenText := string(token.Reveal())
	u, err := url.Parse(store.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: store.ClientTLS(), CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	ledgerDir := t.TempDir()
	jstore, err := jobs.OpenStore(ctx, filepath.Join(ledgerDir, "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jstore.Close() })

	// One runner per rotator: a runner holds one workflow per kind.
	newRunner := func(rot *Rotator) *jobs.Runner {
		r := jobs.NewRunner(jstore, nc)
		r.Register(rot.Workflow())
		return r
	}
	runJob := func(r *jobs.Runner) *jobs.Job {
		t.Helper()
		j, err := r.Submit(ctx, RotateKind, nil, "functional-test")
		if err != nil {
			t.Fatal(err)
		}
		r.Wait()
		got, err := jstore.GetJob(ctx, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	w := &kvWriter{client: client, token: token, progress: make(chan struct{}, 1)}
	startWriter := func() (stop func()) {
		ch := make(chan struct{})
		done := make(chan struct{})
		go func() { defer close(done); w.run(ctx, ch) }()
		return func() { close(ch); <-done }
	}
	// waitFor blocks on writer progress until cond holds, failing if the
	// writer stops making progress because it failed.
	waitFor := func(cond func() bool) {
		t.Helper()
		for !cond() {
			select {
			case <-w.progress:
			case <-ctx.Done():
				t.Fatal("the test's context ended while waiting on the writer")
			}
			if _, errs, _ := w.snapshot(); len(errs) > 0 {
				t.Fatalf("a write failed: %v", errs[0])
			}
		}
	}

	rot, err := NewRotator(Config{Dir: dir, RotateAt: funcRotateAt, KeepBytes: 1 << 30, ReopenWait: 10 * time.Second},
		Deps{Store: client, Reopen: ReopenFunc(store.Reload), Files: OSFiles{}, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	runner := newRunner(rot)
	var jobIDs []string

	t.Run("TC-799-29 rotation under load", func(t *testing.T) {
		stop := startWriter()
		for len(jobIDs) < 3 {
			due := false
			waitFor(func() bool { due, _ = rot.Due(ctx); return due })
			j := runJob(runner)
			jobIDs = append(jobIDs, j.ID)
			if j.Status != jobs.StatusSucceeded {
				stop()
				t.Fatalf("rotation job %s = %s %q, want succeeded", j.ID, j.Status, j.Error)
			}
			evs, err := jstore.ListEvents(ctx, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(stepLogs(t, evs), proto.LogEventData{Level: "info", Message: "audit file rotated"}) {
				t.Errorf("job %s's events lack the 'audit file rotated' step line", j.ID)
			}
		}
		// Let the store write to the newest live file before stopping.
		before, _, _ := w.snapshot()
		waitFor(func() bool { n, _, _ := w.snapshot(); return n >= before+20 })
		stop()
		writes, errs, _ := w.snapshot()
		if len(errs) > 0 {
			t.Fatalf("writes failed: %v", errs)
		}
		if got := len(rec.Matching(slog.LevelInfo, "audit file rotated")); got != 3 {
			t.Errorf("%d 'audit file rotated' INFO records, want 3", got)
		}
		for _, n := range []string{".1", ".2", ".3"} {
			if _, err := os.Stat(filepath.Join(dir, LiveName+n)); err != nil {
				t.Errorf("copy %s: %v", LiveName+n, err)
			}
		}
		if all := sumCounts(responseCounts(t, dir)); all != writes {
			t.Errorf("%d response entries for the writer's paths in all, want %d", all, writes)
		}
		assertNoLineLost(t, dir, 0, writes)
	})

	t.Run("TC-799-30 prune on real copies", func(t *testing.T) {
		copies, err := rot.listCopies()
		if err != nil || len(copies) < 3 {
			t.Fatalf("copies = %v, %v; want at least three", copies, err)
		}
		last := copies[len(copies)-1]
		keep := last.size + copies[len(copies)-2].size
		pruner, err := NewRotator(Config{Dir: dir, RotateAt: funcRotateAt, KeepBytes: keep, ReopenWait: time.Second},
			Deps{Store: client, Reopen: ReopenFunc(store.Reload), Files: OSFiles{}, Log: logger})
		if err != nil {
			t.Fatal(err)
		}
		sc := &jobs.StepCtx{Ctx: ctx, JobID: "prune-test", Log: func(string, string) {}}
		if _, err := pruner.pruneStep(sc); err != nil {
			t.Fatal(err)
		}
		left, err := rot.listCopies()
		if err != nil {
			t.Fatal(err)
		}
		var total int64
		for _, c := range left {
			total += c.size
		}
		if len(left) != 2 || left[1].name != last.name || left[0].seq != copies[len(copies)-2].seq || total > keep {
			t.Errorf("copies after prune = %+v (total %d), want the two newest within %d", left, total, keep)
		}
	})

	t.Run("TC-799-31 forced failure", func(t *testing.T) {
		failing, err := NewRotator(Config{Dir: dir, RotateAt: funcRotateAt, KeepBytes: 1 << 30, ReopenWait: 2 * time.Second},
			Deps{Store: client, Reopen: ReopenFunc(func(context.Context) error { return nil }), Files: OSFiles{}, Log: logger})
		if err != nil {
			t.Fatal(err)
		}
		before, _, _ := w.snapshot()
		stop := startWriter()
		waitFor(func() bool { due, _ := failing.Due(ctx); return due })
		fi, err := os.Stat(store.AuditPath())
		if err != nil {
			stop()
			t.Fatal(err)
		}
		ino, _ := inodeOf(fi)
		listing, err := os.ReadDir(dir)
		if err != nil {
			stop()
			t.Fatal(err)
		}
		j := runJob(newRunner(failing))
		jobIDs = append(jobIDs, j.ID)
		after, _, _ := w.snapshot()
		waitFor(func() bool { n, _, _ := w.snapshot(); return n >= after+20 })
		stop()
		writes, errs, _ := w.snapshot()
		if len(errs) > 0 {
			t.Fatalf("writes failed: %v", errs)
		}
		if writes <= before {
			t.Fatal("the writer made no writes during the failure")
		}

		if j.Status != jobs.StatusFailed || j.Error != string(errRolledBack) {
			t.Fatalf("job = %s %q, want failed with %q", j.Status, j.Error, errRolledBack)
		}
		fi, err = os.Stat(store.AuditPath())
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := inodeOf(fi); got != ino {
			t.Errorf("live inode = %d, want the original %d", got, ino)
		}
		now, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		names := func(es []os.DirEntry) []string {
			var out []string
			for _, e := range es {
				out = append(out, e.Name())
			}
			return out
		}
		if !slices.Equal(names(now), names(listing)) {
			t.Errorf("dir = %v after the failed attempt, want %v", names(now), names(listing))
		}
		svc := alertsOver(t, jstore)
		list, err := svc.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, a := range list {
			if a.ID == "job-failed:"+j.ID {
				found = true
				if a.Detail != string(errRolledBack) || strings.Contains(a.Detail, "/") {
					t.Errorf("job-failed detail = %q, want the rolled-back sentence", a.Detail)
				}
			}
		}
		if !found {
			t.Errorf("alerts = %+v, want job-failed:%s", list, j.ID)
		}
		errs2 := rec.Matching(slog.LevelError, "rotation rolled back")
		if len(errs2) != 1 {
			t.Fatalf("%d 'rotation rolled back' ERROR records, want 1", len(errs2))
		}
		if got, _ := logkittest.Attr(errs2[0], "job_id"); got != j.ID {
			t.Errorf("ERROR job_id = %q, want %q", got, j.ID)
		}
		assertNoLineLost(t, dir, before, writes)
	})

	t.Run("TC-799-32 no secret in logs or job events", func(t *testing.T) {
		_, _, values := w.snapshot()
		var events strings.Builder
		for _, id := range jobIDs {
			evs, err := jstore.ListEvents(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(evs)
			events.Write(b)
		}
		logs := rec.Text()
		for _, s := range append([]string{tokenText}, values...) {
			if strings.Contains(logs, s) || strings.Contains(events.String(), s) {
				t.Fatalf("a token or KV value reached the logs or the job events")
			}
		}
	})
}

// alertsOver is an alerts.Service over the test's job ledger, with empty
// inventory, apps and setup stores.
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

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
