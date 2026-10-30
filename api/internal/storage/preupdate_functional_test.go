package storage

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The OS update's copy of the store and the reference check after it is put
// back, against the real pinned store (geekdojo/geekdojo-brain#800,
// TC-800-22 to TC-800-25; docs/testing-secret-store.md).

const (
	fnAppX       = "01JABCDEFGHJKMNPQRSTVWXYZ1"
	fnAppY       = "01JABCDEFGHJKMNPQRSTVWXYZ2"
	fnSecretName = "db-pass"
	fnCompose    = "services:\n  db:\n    environment:\n      PW: ${secret:db-pass}\n"
)

// updateControl is realControl quiescing for an OS update.
type updateControl struct{ *realControl }

func (c updateControl) Quiesce(jobID string) func() {
	return c.rs.mon.Quiesce(jobID, storestate.QuiesceOSUpdate)
}

// appsAt places every app on the run harness's node, from the apps table.
type appsAt struct{ s *apps.Store }

func (a appsAt) TargetNode(ctx context.Context, appID string) (string, bool, error) {
	app, err := a.s.Get(ctx, appID)
	if err != nil || app == nil {
		return "", false, err
	}
	return runNodeID, true, nil
}

// refsOf is the apps table's references as appsecret reads them.
type refsOf struct{ s *apps.Store }

func (r refsOf) ListSecretRefs(ctx context.Context) ([]appsecret.SecretRef, error) {
	rows, err := r.s.ListSecretRefs(ctx)
	out := make([]appsecret.SecretRef, 0, len(rows))
	for _, x := range rows {
		out = append(out, appsecret.SecretRef{AppID: x.AppID, Name: x.Name})
	}
	return out, err
}

func TestPreUpdateCopy_AgainstTheRealStore(t *testing.T) {
	bin := os.Getenv(storeBinEnv)
	if bin == "" {
		functest.SkipOrFail(t, storeSwitchEnv, "%s is not set, so there is no secret store binary to run", storeBinEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, storeSwitchEnv, "%s=%s: no secret store binary there: %v", storeBinEnv, bin, err)
		return
	}
	ctx := t.Context()
	logger, rec := logkittest.New()
	hs, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader, ExternalSeal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st := startRealStore(t, hs)
	h := newRunHarness(t, nil, runHarnessOpts{})
	rs := apiChain(t, st, logger, harnessJobRunning(&h))

	dir := t.TempDir()
	appStore, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appStore.Close() })
	now := time.Now().UTC()
	for _, id := range []string{fnAppX, fnAppY} {
		if err := appStore.Create(ctx, &apps.App{ID: id, Name: "app-" + id, TargetNode: runNodeID, ComposeYAML: fnCompose, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := secrets.NewService(secrets.Deps{Repo: rs.repo, Apps: appsAt{appStore}, Switch: realSwitch(t, logger), Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := appsecret.EnsureSeed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: appsAt{appStore}, Refs: appStore, Seed: seed, Operator: noDecls{}, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	derived := func(app string) string {
		v, err := seed.Derive(app, fnSecretName, appsecret.InitialVersion)
		if err != nil {
			t.Fatal(err)
		}
		defer v.Destroy()
		return string(v.Reveal())
	}
	resolve := func(app string) string {
		t.Helper()
		// The values travel beside the compose since #776; what this test
		// checks is which value the app resolved to, so that is returned.
		v, env, err := src.ResolveCompose(jobs.ContextWithJobID(ctx, "deploy-"+app), app, fnCompose)
		if err != nil {
			t.Fatalf("resolve %s: %v", app, err)
		}
		defer v.Destroy()
		var out strings.Builder
		for _, e := range env {
			out.Write(e.Reveal())
			out.WriteByte('\n')
			e.Destroy()
		}
		return out.String()
	}
	valueX, valueY := derived(fnAppX), derived(fnAppY)

	// 1. X is resolved through the store, which creates and records it.
	if got := resolve(fnAppX); !strings.Contains(got, valueX) {
		t.Fatal("X did not resolve to its derived value")
	}

	// TC-800-22: the copy, through the copier, inside a job.
	gate, err := sealrotate.NewGate(rs.files, harnessJobRunning(&h), logger)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "openbao-preupdate.tar")
	copier, err := NewPreUpdateCopier(PreUpdateCopierDeps{Store: updateControl{&realControl{rs: rs}}, Lock: gate,
		DataDir: st.DataDir(), CopyPath: copyPath, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Register(jobs.Workflow{Kind: "test.copy_store", Steps: []jobs.WorkflowStep{{Name: "copy_store", Timeout: time.Minute, Do: copier.CopyBeforeUpdate}}})
	cj, err := h.runner.Submit(ctx, "test.copy_store", nil, "functional-test")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.waitTerminal(t, cj.ID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("copy %s: %s", j.Status, j.Error)
	}
	hl, err := rs.client.Health(ctx)
	if err != nil || hl.Sealed || !hl.Initialized {
		t.Fatalf("the store after its copy: %+v, %v", hl, err)
	}
	if v := tarMembers(t, copyPath)[storeVersionArchivePath]; v != hl.Version {
		t.Errorf("%s = %q, sys/health says %q", storeVersionArchivePath, v, hl.Version)
	}
	lines := jobLines(t, h, cj.ID)
	for _, want := range []string{"secret store stopped for its cold copy", "secret store copied before the update"} {
		if !strings.Contains(lines, want) {
			t.Errorf("copy job lines lack %q:\n%s", want, lines)
		}
	}

	// 3. Y is created after the copy.
	if got := resolve(fnAppY); !strings.Contains(got, valueY) {
		t.Fatal("Y did not resolve to its derived value")
	}

	// TC-800-23: the copy is put back with the store stopped, and the check
	// names exactly Y's entry, raises its job-failed alert and logs its
	// lines.
	if err := st.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	putBack(t, copyPath, st.DataDir())
	if err := st.StartNoWait(ctx); err != nil {
		t.Fatal(err)
	}
	if err := secretstore.WaitReady(ctx, rs.client, sealrotate.UnsealWait); err != nil {
		t.Fatal(err)
	}
	wf, err := appsecret.ReferenceCheckWorkflow(appsecret.ReferenceCheckDeps{Refs: refsOf{appStore}, Secrets: svc, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Register(wf)
	kj, err := h.runner.Submit(ctx, appsecret.ReferenceCheckKind, nil, "store-ready")
	if err != nil {
		t.Fatal(err)
	}
	j := h.waitTerminal(t, kj.ID)
	refY := "apps/" + fnAppY + "/" + fnSecretName
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, refY) || strings.Contains(j.Error, fnAppX) {
		t.Fatalf("check %s %q, want failed naming exactly %s", j.Status, j.Error, refY)
	}
	alertSvc := newFunctionalAlerts(t, h)
	list, err := alertSvc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range list {
		found = found || (a.ID == "job-failed:"+kj.ID && a.Detail == j.Error)
	}
	if !found {
		t.Errorf("no job-failed alert for the check in %+v", list)
	}
	if kl := jobLines(t, h, kj.ID); !strings.Contains(kl, "missing from the secret store: "+refY) {
		t.Errorf("check job lines lack the missing reference:\n%s", kl)
	}

	// TC-800-24: Y is never served empty: it resolves again to its derived
	// value.
	if got := resolve(fnAppY); !strings.Contains(got, valueY) {
		t.Error("Y did not resolve to its derived value after the put-back")
	}

	// TC-800-25: no secret value and no store data bytes in any record or
	// job line.
	all := rec.Text() + jobLines(t, h, cj.ID) + jobLines(t, h, kj.ID)
	for name, v := range map[string]string{"X's value": valueX, "Y's value": valueY} {
		if strings.Contains(all, v) {
			t.Errorf("%s reached a log record or job line", name)
		}
	}
}

// putBack replaces dataDir's contents with the copy's store/data members.
func putBack(t *testing.T, copyPath, dataDir string) {
	t.Helper()
	ents, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dataDir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		rel, ok := strings.CutPrefix(hdr.Name, storeDataArchivePrefix)
		if !ok {
			continue
		}
		dst := filepath.Join(dataDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// jobLines is every log line of the job, one per line.
func jobLines(t *testing.T, h *runHarness, jobID string) string {
	t.Helper()
	evs, err := h.jobStore.ListEvents(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range evs {
		b.Write(e.Data)
		b.WriteByte('\n')
	}
	return b.String()
}

// newFunctionalAlerts is the alert service over the harness's job ledger.
func newFunctionalAlerts(t *testing.T, h *runHarness) *alerts.Service {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
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
	inv := h.inv
	if inv == nil {
		inv = newInventory(t)
	}
	return alerts.New(inv, h.jobStore, as, setup.NewService(ss, setup.Probes{}, "", "", ""), nil, nil, true)
}

// noDecls is an app that declares no operator secrets.
type noDecls struct{}

func (noDecls) OperatorSecrets(context.Context, string) ([]tileschema.OperatorSecret, error) {
	return nil, nil
}
