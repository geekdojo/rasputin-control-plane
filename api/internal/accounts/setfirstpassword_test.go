package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// accounts.set_first_password (geekdojo/geekdojo-brain#1005) over the
// Admin API fake, the real Users, a real policy checker over a staged
// list, the real removed-name list, and the job on an authorized runner
// the kind table decides.

const (
	movedSub   = "moved-sub"
	movedEmail = "moved@example.org"
)

// recFacts records RecordPasswordSet, or fails with err.
type recPasswordFacts struct {
	mu   sync.Mutex
	subs []string
	err  error
}

func (f *recPasswordFacts) RecordPasswordSet(_ context.Context, sub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.subs = append(f.subs, sub)
	return nil
}

func (f *recPasswordFacts) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.subs)
}

type firstHarness struct {
	*harness
	fp        *FirstPassword
	pws, mail *Held
	facts     *recPasswordFacts
	runner    *jobs.Runner
	listDir   string
	rlog      *logkittest.Recorder
	// heldAtPrepare is what Held held for the job when prepare returned.
	heldPw, heldEmail string
	heldJob           string
}

func newFirstHarness(t *testing.T) *firstHarness {
	t.Helper()
	h := &firstHarness{harness: newHarness(t), pws: NewHeld(), mail: NewHeld(), facts: &recPasswordFacts{}, listDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(h.listDir, flows.DenylistFile), []byte(listedPw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checker, err := pwpolicy.New(h.listDir, flows.PasswordPolicy)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := authz.NewKindPolicy(noApps{})
	if err != nil {
		t.Fatal(err)
	}
	if h.runner, err = jobs.NewAuthorizedRunner(h.jobs, h.nc, kp); err != nil {
		t.Fatal(err)
	}
	// The runner as Set sees it, snapshotting Held once prepare has run.
	sub := submitterFunc(func(ctx context.Context, by authz.Submitter, kind string, spec any, prepare func(string) error) (*jobs.Job, error) {
		return h.runner.SubmitFor(ctx, by, kind, spec, func(id string) error {
			if err := prepare(id); err != nil {
				return err
			}
			h.heldJob = id
			if v, ok := h.pws.Take(id); ok {
				h.heldPw = string(v.Reveal())
				h.pws.Put(id, v)
			}
			if v, ok := h.mail.Take(id); ok {
				h.heldEmail = string(v.Reveal())
				h.mail.Put(id, v)
			}
			return nil
		})
	})
	slogger, rec := logkittest.New()
	h.rlog = rec
	if h.fp, err = NewFirstPassword(FirstPasswordDeps{Users: h.users, Checker: checker, Removed: h.removed, Facts: h.facts,
		Runner: sub, Passwords: h.pws, Emails: h.mail, Lock: h.lock, Log: slogger, StepTimeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	h.runner.Register(h.fp.Workflow())
	// A moved account: no email, no credential, the recovery-codes action.
	h.kc.add(person{sub: movedSub, name: "b-1", enabled: true, appRole: "user", actions: []any{"CONFIGURE_RECOVERY_AUTHN_CODES"}})
	// The reset-password write adds the password credential, as the
	// identity service does.
	h.kc.observe = func(method, rel string) {
		if method == http.MethodPut && strings.HasSuffix(rel, "/reset-password") {
			id := strings.Split(strings.Trim(rel, "/"), "/")[1]
			h.kc.mu.Lock()
			if x := h.kc.users[id]; x != nil && h.kc.fail == nil {
				x.creds = append(x.creds, "password")
				x.credIDs = append(x.credIDs, "id-password")
			}
			h.kc.mu.Unlock()
		}
	}
	return h
}

func (h *firstHarness) set(t *testing.T, pw, email string) error {
	t.Helper()
	p, e := secret.New([]byte(pw)), secret.New([]byte(email))
	defer p.Destroy()
	defer e.Destroy()
	err := h.fp.Set(t.Context(), authz.BridgeGrant(movedSub), movedSub, p, e)
	h.runner.Wait()
	return err
}

func (h *firstHarness) check(t *testing.T, pw, email string) error {
	t.Helper()
	return h.fp.Check(t.Context(), movedSub, secret.New([]byte(pw)), secret.New([]byte(email)))
}

func refusalCode(err error) string {
	var ref *auth.BridgeRefusal
	if errors.As(err, &ref) {
		return ref.Code
	}
	return ""
}

func (h *firstHarness) rep(sub string) map[string]any {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	return h.kc.users[sub].rep
}

func (h *firstHarness) creds(sub string) []string {
	h.kc.mu.Lock()
	defer h.kc.mu.Unlock()
	return slices.Clone(h.kc.users[sub].creds)
}

func (h *firstHarness) lastJob(t *testing.T) result {
	t.Helper()
	js, err := h.jobs.ListJobsByKind(t.Context(), FirstPasswordKind, 10)
	if err != nil || len(js) == 0 {
		t.Fatalf("jobs %v %v", js, err)
	}
	return h.result(t, js[0].ID)
}

// TC-1005-14 (issue TC-03): the persisted spec is exactly
// {"accountId":"<sub>"}; the password and the email are in the two Held
// instances under the job id when the job starts, and neither appears in
// the job's or its steps' rows or the log.
func TestFirstPassword_TC1005_14_SpecHoldsNoSecret(t *testing.T) {
	h := newFirstHarness(t)
	if err := h.set(t, goodPw, movedEmail); err != nil {
		t.Fatal(err)
	}
	r := h.result(t, h.heldJob)
	if string(r.job.Spec) != `{"accountId":"`+movedSub+`"}` {
		t.Errorf("spec %s", r.job.Spec)
	}
	if h.heldPw != goodPw || h.heldEmail != movedEmail {
		t.Errorf("Held at prepare: %q %q", h.heldPw, h.heldEmail)
	}
	if r.job.CreatedBy != movedSub {
		t.Errorf("created by %q", r.job.CreatedBy)
	}
	var rows []byte
	for _, b := range []any{r.job, r.steps} {
		raw, _ := json.Marshal(b)
		rows = append(rows, raw...)
	}
	for _, leak := range []string{goodPw, movedEmail} {
		if strings.Contains(string(rows), leak) || strings.Contains(h.rlog.Text(), leak) {
			t.Errorf("%q appears in the ledger or the log", leak)
		}
	}
	if h.pws.size() != 0 || h.mail.size() != 0 {
		t.Error("the terminal hook left a value held")
	}
}

// TC-1005-15 (issue TC-02): an account that holds a password is refused
// has_password, with no email or password write.
func TestFirstPassword_TC1005_15_RefusesAnAccountWithAPassword(t *testing.T) {
	h := newFirstHarness(t)
	h.kc.mu.Lock()
	h.kc.users[movedSub].creds = []string{"password"}
	h.kc.users[movedSub].credIDs = []string{"id-pw"}
	h.kc.mu.Unlock()
	err := h.set(t, goodPw, movedEmail)
	if refusalCode(err) != auth.BridgeCodeHasPassword {
		t.Errorf("Set: %v", err)
	}
	r := h.lastJob(t)
	if r.job.Status != jobs.StatusFailed || r.job.Error != auth.SentenceHasPassword {
		t.Errorf("job %s %q", r.job.Status, r.job.Error)
	}
	for _, c := range h.log.all() {
		if c == "set-email" || c == "reset-password" {
			t.Errorf("a write ran: %v", h.log.all())
		}
	}
}

// TC-1005-16: the success writes and each failure path.
func TestFirstPassword_TC1005_16_Outcomes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h := newFirstHarness(t)
		if err := h.set(t, goodPw, movedEmail); err != nil {
			t.Fatal(err)
		}
		rep := h.rep(movedSub)
		if rep["email"] != movedEmail || attrOf(rep["attributes"], "rasputin_email") != "" {
			t.Errorf("email %v, confirmed %q", rep["email"], attrOf(rep["attributes"], "rasputin_email"))
		}
		var body map[string]any
		for _, rq := range h.kc.reqs {
			if strings.HasSuffix(rq.path, "/reset-password") {
				_ = json.Unmarshal(rq.body, &body)
			}
		}
		if body["temporary"] != false || body["value"] != goodPw || body["type"] != "password" {
			t.Errorf("the password write: %v", body["temporary"])
		}
		if got := h.facts.recorded(); !slices.Equal(got, []string{movedSub}) {
			t.Errorf("facts %v", got)
		}
		if recs := h.rlog.Matching(slog.LevelInfo, "set"); len(recs) != 1 {
			t.Errorf("log %s", h.rlog.Text())
		}
	})
	t.Run("a failed fact write still succeeds", func(t *testing.T) {
		h := newFirstHarness(t)
		h.facts.err = errors.New("disk")
		if err := h.set(t, goodPw, movedEmail); err != nil {
			t.Fatal(err)
		}
		if recs := h.rlog.Matching(slog.LevelWarn, "fact"); len(recs) != 1 {
			t.Errorf("log %s", h.rlog.Text())
		}
	})
	t.Run("a removed email", func(t *testing.T) {
		h := newFirstHarness(t)
		if err := h.removed.Record(t.Context(), "gone", movedEmail); err != nil {
			t.Fatal(err)
		}
		err := h.set(t, goodPw, movedEmail)
		if refusalCode(err) != auth.BridgeCodeNotSet || err.(*auth.BridgeRefusal).Sentence != sentenceEmailListed {
			t.Errorf("Set: %v", err)
		}
	})
	t.Run("an email taken: 409", func(t *testing.T) {
		h := newFirstHarness(t)
		h.kc.add(person{sub: "other", name: "other", email: movedEmail, enabled: true})
		err := h.set(t, goodPw, movedEmail)
		if r := h.lastJob(t); r.job.Error != sentenceEmailTaken || refusalCode(err) != auth.BridgeCodeNotSet {
			t.Errorf("job %q, Set %v", r.job.Error, err)
		}
	})
	fail500 := func(h *firstHarness) {
		h.kc.fail = func(method, path string) error {
			if strings.HasSuffix(path, "/reset-password") {
				return &idclient.Error{Op: "admin", Path: path, Status: 500, Kind: idclient.ErrUnreachable}
			}
			return nil
		}
	}
	t.Run("a 500 the policy refuses", func(t *testing.T) {
		h := newFirstHarness(t)
		fail500(h)
		if err := h.set(t, listedPw, movedEmail); err == nil || err.(*auth.BridgeRefusal).Sentence != "That password is too common. Choose another." {
			t.Errorf("Set: %v", err)
		}
		if recs := h.rlog.Matching(slog.LevelWarn, "refused"); len(recs) != 1 {
			t.Errorf("log %s", h.rlog.Text())
		}
	})
	t.Run("a 500 the policy does not refuse", func(t *testing.T) {
		h := newFirstHarness(t)
		fail500(h)
		if err := h.set(t, goodPw, movedEmail); err == nil || err.(*auth.BridgeRefusal).Sentence != sentenceFirstSetFailed {
			t.Errorf("Set: %v", err)
		}
		recs := h.rlog.Matching(slog.LevelError, "failed")
		if len(recs) != 1 {
			t.Fatalf("log %s", h.rlog.Text())
		}
		if s, _ := logkittest.Attr(recs[0], "status"); s != "500" {
			t.Errorf("status %q", s)
		}
	})
	t.Run("nothing held", func(t *testing.T) {
		h := newFirstHarness(t)
		j, err := h.runner.SubmitFor(t.Context(), authz.BridgeGrant(movedSub), FirstPasswordKind, FirstPasswordSpec{AccountID: movedSub}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.runner.Wait()
		if r := h.result(t, j.ID); r.job.Status != jobs.StatusFailed || r.job.Error != sentenceFirstNotHeld {
			t.Errorf("job %s %q", r.job.Status, r.job.Error)
		}
	})
	t.Run("a bridge grant for another account is refused before any job", func(t *testing.T) {
		h := newFirstHarness(t)
		err := h.fp.Set(t.Context(), authz.BridgeGrant("someone-else"), movedSub, secret.New([]byte(goodPw)), secret.New([]byte(movedEmail)))
		if err == nil || h.pws.size() != 0 || h.mail.size() != 0 {
			t.Errorf("Set: %v, held %d %d", err, h.pws.size(), h.mail.size())
		}
	})
	t.Run("Set returns the context's error when the request ends first", func(t *testing.T) {
		h := newFirstHarness(t)
		release := make(chan struct{})
		reached := make(chan struct{}, 1)
		h.kc.observe = func(method, rel string) {
			if strings.HasSuffix(rel, "/credentials") {
				reached <- struct{}{}
				<-release
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- h.fp.Set(ctx, authz.BridgeGrant(movedSub), movedSub, secret.New([]byte(goodPw)), secret.New([]byte(movedEmail)))
		}()
		<-reached
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Set: %v", err)
		}
		close(release)
		h.runner.Wait()
		if h.pws.size() != 0 || h.mail.size() != 0 {
			t.Error("the terminal hook left a value held")
		}
	})
	t.Run("an unreadable credentials list", func(t *testing.T) {
		h := newFirstHarness(t)
		h.kc.fail = func(method, path string) error {
			if strings.HasSuffix(path, "/credentials") {
				return &idclient.Error{Op: "admin", Path: path, Status: 503, Kind: idclient.ErrUnreachable}
			}
			return nil
		}
		if err := h.set(t, goodPw, movedEmail); err == nil || err.(*auth.BridgeRefusal).Sentence != sentenceFirstSetFailed {
			t.Errorf("Set: %v", err)
		}
	})
	if _, err := NewFirstPassword(FirstPasswordDeps{}); err == nil {
		t.Error("NewFirstPassword accepted no collaborators")
	}
}

// TC-1005-11 (F-1005-03): after a half-failed job left the account's own
// email E and no password, a new attempt with E passes Check and sets the
// password. Check's other refusals, in order, and HasPassword.
func TestFirstPassword_TC1005_11_Check(t *testing.T) {
	h := newFirstHarness(t)
	// The half-failed run: the email write landed, the password write
	// didn't.
	h.kc.fail = func(method, path string) error {
		if strings.HasSuffix(path, "/reset-password") {
			return &idclient.Error{Op: "admin", Path: path, Status: 400, Kind: idclient.ErrProtocol}
		}
		return nil
	}
	if err := h.set(t, goodPw, movedEmail); refusalCode(err) != auth.BridgeCodeNotSet {
		t.Fatalf("the half-failed run: %v", err)
	}
	if h.rep(movedSub)["email"] != movedEmail || slices.Contains(h.creds(movedSub), "password") {
		t.Fatalf("the fixture: email %v creds %v", h.rep(movedSub)["email"], h.creds(movedSub))
	}
	h.kc.fail = nil
	if err := h.check(t, goodPw, "MOVED@example.org"); err != nil {
		t.Errorf("Check with the account's own email: %v", err)
	}
	if err := h.set(t, goodPw, movedEmail); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if got := h.creds(movedSub); !slices.Equal(got, []string{"password"}) {
		t.Errorf("credentials %v, want [password]", got)
	}

	// Another account's email; a removed email; the policy; an unreadable
	// list; an unreadable account.
	h2 := newFirstHarness(t)
	h2.kc.add(person{sub: "other", name: "other", email: "taken@example.org", enabled: true})
	if err := h2.removed.Record(t.Context(), "gone", "gone@example.org"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ pw, email, code string }{
		{goodPw, "taken@example.org", auth.BridgeCodeEmailTaken},
		{goodPw, "gone@example.org", auth.BridgeCodeEmailListed},
		{listedPw, movedEmail, auth.BridgeCodePasswordRefused},
	} {
		if got := refusalCode(h2.check(t, c.pw, c.email)); got != c.code {
			t.Errorf("Check(%q): %q, want %q", c.email, got, c.code)
		}
	}
	if err := os.Remove(filepath.Join(h2.listDir, flows.DenylistFile)); err != nil {
		t.Fatal(err)
	}
	if got := refusalCode(h2.check(t, goodPw, movedEmail)); got != auth.BridgeCodePasswordCheckUnavailable {
		t.Errorf("an unreadable list: %q", got)
	}
	if recs := h2.rlog.Matching(slog.LevelError, "deny list"); len(recs) != 1 {
		t.Errorf("log %s", h2.rlog.Text())
	}
	if err := h2.fp.Check(t.Context(), "nobody", secret.New([]byte(goodPw)), secret.New([]byte(movedEmail))); err == nil || refusalCode(err) != "" {
		t.Errorf("an unreadable account: %v", err)
	}

	// HasPassword: false, then true with the fact recorded.
	h3 := newFirstHarness(t)
	if has, err := h3.fp.HasPassword(t.Context(), movedSub); err != nil || has || len(h3.facts.recorded()) != 0 {
		t.Errorf("HasPassword with none: %v %v", has, err)
	}
	h3.kc.mu.Lock()
	h3.kc.users[movedSub].creds, h3.kc.users[movedSub].credIDs = []string{"password"}, []string{"id"}
	h3.kc.mu.Unlock()
	if has, err := h3.fp.HasPassword(t.Context(), movedSub); err != nil || !has || !slices.Equal(h3.facts.recorded(), []string{movedSub}) {
		t.Errorf("HasPassword with one: %v %v %v", has, err, h3.facts.recorded())
	}
	h3.facts.err = errors.New("disk")
	if has, err := h3.fp.HasPassword(t.Context(), movedSub); err != nil || !has {
		t.Errorf("HasPassword with a failed fact write: %v %v", has, err)
	}
	if _, err := h3.fp.HasPassword(t.Context(), "nobody"); err == nil {
		t.Error("HasPassword of no account")
	}
}
