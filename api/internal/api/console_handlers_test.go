package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const testConsolePassword = "a perfectly fine console password"

func decodeConsoleSet(t *testing.T, body []byte) consoleSetResponse {
	t.Helper()
	var resp consoleSetResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	return resp
}

func decodeConsoleStatus(t *testing.T, body []byte) console.Status {
	t.Helper()
	var st console.Status
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	return st
}

func TestConsoleRootPassword_RequireAuth(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/console/root-password", ""},
		{http.MethodPut, "/api/console/root-password", `{"password":"` + testConsolePassword + `"}`},
		{http.MethodPost, "/api/console/root-password/push", ""},
	} {
		w := f.do(t, tc.method, tc.path, tc.body, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a cookie: want 401, got %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestConsoleRootPassword_UnsetThenSet(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})

	w := f.do(t, http.MethodGet, "/api/console/root-password", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	if st := decodeConsoleStatus(t, w.Body.Bytes()); st.Set || st.HashID != "" || len(st.Nodes) != 0 {
		t.Fatalf("a fresh install reads as %+v", st)
	}

	w = f.do(t, http.MethodPut, "/api/console/root-password", `{"password":"`+testConsolePassword+`"}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	resp := decodeConsoleSet(t, w.Body.Bytes())
	if resp.HashID == "" {
		t.Fatal("PUT returned no password id")
	}
	if resp.JobID == "" || resp.PushError != "" {
		t.Fatalf("PUT did not submit the push: %+v", resp)
	}

	w = f.do(t, http.MethodGet, "/api/console/root-password", "", c)
	st := decodeConsoleStatus(t, w.Body.Bytes())
	if !st.Set || st.HashID != resp.HashID || st.SetAt == nil {
		t.Fatalf("after the PUT: %+v", st)
	}
}

// The endpoint's whole reason for existing: the password goes in and
// nothing that comes back out, ever, carries it or its hash.
func TestConsoleRootPassword_NeverReturnsTheSecret(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})

	w := f.do(t, http.MethodPut, "/api/console/root-password", `{"password":"`+testConsolePassword+`"}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	putBody := w.Body.String()

	hashValue, _, err := f.console.HashForDispatch(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	hash := string(hashValue.Reveal())
	w = f.do(t, http.MethodGet, "/api/console/root-password", "", c)
	getBody := w.Body.String()

	// And the wizard state, which is served UNAUTHENTICATED.
	w = f.do(t, http.MethodGet, "/api/setup/state", "", nil)
	stateBody := w.Body.String()

	for name, body := range map[string]string{
		"the PUT response":             putBody,
		"the GET response":             getBody,
		"the wizard state":             stateBody,
		"the job ledger the PUT wrote": jobsBody(t, f, c),
	} {
		for _, secret := range []string{hash, testConsolePassword, "$6$"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s carries %q:\n%s", name, secret, body)
			}
		}
	}
	// The wizard does say a password is set — that fact is not secret.
	if !strings.Contains(stateBody, `"consoleRootSet":true`) {
		t.Errorf("the wizard does not report the step as done:\n%s", stateBody)
	}
}

func jobsBody(t *testing.T, f *apiFixture, c *http.Cookie) string {
	t.Helper()
	return f.do(t, http.MethodGet, "/api/jobs", "", c).Body.String()
}

func TestConsoleRootPassword_RefusesAPasswordTheConsoleCouldNotTake(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})
	for name, body := range map[string]string{
		"empty":       `{"password":""}`,
		"too short":   `{"password":"short"}`,
		"newline":     `{"password":"long enough but has a \n in it"}`,
		"missing key": `{}`,
		"bad json":    `{`,
	} {
		w := f.do(t, http.MethodPut, "/api/console/root-password", body, c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", name, w.Code, w.Body.String())
		}
	}
	w := f.do(t, http.MethodGet, "/api/console/root-password", "", c)
	if st := decodeConsoleStatus(t, w.Body.Bytes()); st.Set {
		t.Error("a refused password was stored anyway")
	}
}

// The Settings action is re-runnable, and refuses when there is nothing to
// apply rather than dispatching an empty hash.
func TestConsoleRootPassword_PushAction(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})

	w := f.do(t, http.MethodPost, "/api/console/root-password/push", "", c)
	if w.Code != http.StatusConflict {
		t.Fatalf("push with no password: want 409, got %d %s", w.Code, w.Body.String())
	}

	if _, err := f.console.SetPassword(f.ctx, testConsolePassword); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		w = f.do(t, http.MethodPost, "/api/console/root-password/push", "", c)
		if w.Code != http.StatusAccepted {
			t.Fatalf("push %d: want 202, got %d %s", i, w.Code, w.Body.String())
		}
		if resp := decodeConsoleSet(t, w.Body.Bytes()); resp.JobID == "" {
			t.Fatalf("push %d returned no job", i)
		}
	}
}

// Storing without pushing is a valid wizard path (nodes not up yet).
func TestConsoleRootPassword_PutWithoutPush(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPut, "/api/console/root-password",
		`{"password":"`+testConsolePassword+`","push":false}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	if resp := decodeConsoleSet(t, w.Body.Bytes()); resp.JobID != "" {
		t.Fatalf("push:false still submitted %s", resp.JobID)
	}
	if id, _ := f.console.CurrentHashID(f.ctx); id == "" {
		t.Fatal("push:false did not store the password")
	}
}

// Removing a node drops its console record, so it stops being counted as a
// node that never took the password.
func TestConsoleRootPassword_NodeRemovalForgetsTheRecord(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	if _, err := f.console.SetPassword(f.ctx, testConsolePassword); err != nil {
		t.Fatal(err)
	}
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "compute9", Role: proto.RoleCompute, Hostname: "compute9"}); err != nil {
		t.Fatal(err)
	}
	if err := f.console.RecordNode(f.ctx, console.NodeState{
		NodeID: "compute9", Status: console.NodeFailed, Detail: "old agent",
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodDelete, "/api/nodes/compute9", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body.String())
	}
	st, err := f.console.Status(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.Nodes {
		if n.NodeID == "compute9" {
			t.Fatalf("a removed node is still reported: %+v", n)
		}
	}
}

// consoleRecords returns the captured server records with message msg.
func consoleRecords(f *apiFixture, msg string) []slog.Record {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	var out []slog.Record
	for _, r := range f.logs.recs {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// allLogText renders every captured server record, fields included.
func allLogText(f *apiFixture) string {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	var b strings.Builder
	for _, r := range f.logs.recs {
		b.WriteString(r.Message)
		r.Attrs(func(a slog.Attr) bool {
			b.WriteString(" " + a.Key + "=" + a.Value.String())
			return true
		})
		b.WriteString("\n")
	}
	return b.String()
}

// TC-597-12: both Settings endpoints return a job the operator can follow,
// and that job is a console.root_push.
func TestConsoleRootPassword_SettingsActionsReturnAFollowableJob(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})

	put := f.do(t, http.MethodPut, "/api/console/root-password", `{"password":"`+testConsolePassword+`"}`, c)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", put.Code, put.Body.String())
	}
	post := f.do(t, http.MethodPost, "/api/console/root-password/push", "", c)
	if post.Code != http.StatusAccepted {
		t.Fatalf("POST: %d %s", post.Code, post.Body.String())
	}
	for name, body := range map[string][]byte{"PUT": put.Body.Bytes(), "POST": post.Body.Bytes()} {
		id := decodeConsoleSet(t, body).JobID
		if id == "" {
			t.Fatalf("%s returned no jobId: %s", name, body)
		}
		w := f.do(t, http.MethodGet, "/api/jobs/"+id, "", c)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: GET /api/jobs/%s: %d %s", name, id, w.Code, w.Body.String())
		}
		var j struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
			t.Fatal(err)
		}
		if j.Kind != console.PushKind {
			t.Errorf("%s: job %s is %q, want %q", name, id, j.Kind, console.PushKind)
		}
	}
}

// TC-597-13: each stored password writes one INFO record carrying its id,
// whether it was pushed, and the job applying it when there is one.
func TestConsoleRootPassword_PutJournalsTheChange(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})
	const msg = "console: console root password set"

	w := f.do(t, http.MethodPut, "/api/console/root-password", `{"password":"`+testConsolePassword+`"}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	resp := decodeConsoleSet(t, w.Body.Bytes())
	recs := consoleRecords(f, msg)
	if len(recs) != 1 || recs[0].Level != slog.LevelInfo {
		t.Fatalf("%d %q records after the first PUT, want one INFO:\n%s", len(recs), msg, allLogText(f))
	}
	for key, want := range map[string]string{"hash_id": resp.HashID, "push": "true", "job_id": resp.JobID} {
		if got, ok := recAttr(recs[0], key); !ok || got != want {
			t.Errorf("first record %s = %q (present %v), want %q", key, got, ok, want)
		}
	}

	w = f.do(t, http.MethodPut, "/api/console/root-password",
		`{"password":"a different console password","push":false}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT push:false: %d %s", w.Code, w.Body.String())
	}
	resp = decodeConsoleSet(t, w.Body.Bytes())
	recs = consoleRecords(f, msg)
	if len(recs) != 2 {
		t.Fatalf("%d %q records after the second PUT, want 2", len(recs), msg)
	}
	if got, _ := recAttr(recs[1], "push"); got != "false" {
		t.Errorf("second record push = %q, want false", got)
	}
	if got, _ := recAttr(recs[1], "hash_id"); got != resp.HashID {
		t.Errorf("second record hash_id = %q, want %q", got, resp.HashID)
	}
	if _, ok := recAttr(recs[1], "job_id"); ok {
		t.Error("a PUT that submitted no job logged a job_id")
	}
	text := allLogText(f)
	for _, secret := range []string{testConsolePassword, "a different console password", "$6$"} {
		if strings.Contains(text, secret) {
			t.Errorf("the server log carries %q:\n%s", secret, text)
		}
	}
}

// TC-597-14: a stored password whose push did not start is an ERROR record,
// and the password is still stored.
func TestConsoleRootPassword_PutWhosePushDidNotStartIsAnError(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// No console.root_push workflow registered: Submit refuses the kind.

	w := f.do(t, http.MethodPut, "/api/console/root-password", `{"password":"`+testConsolePassword+`"}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	resp := decodeConsoleSet(t, w.Body.Bytes())
	if resp.PushError == "" || resp.JobID != "" {
		t.Fatalf("response = %+v, want a pushError and no jobId", resp)
	}
	g := f.do(t, http.MethodGet, "/api/console/root-password", "", c)
	if st := decodeConsoleStatus(t, g.Body.Bytes()); !st.Set {
		t.Fatal("the password was not stored")
	}
	var errs []slog.Record
	f.logs.mu.Lock()
	for _, r := range f.logs.recs {
		if r.Level == slog.LevelError {
			errs = append(errs, r)
		}
	}
	f.logs.mu.Unlock()
	if len(errs) != 1 {
		t.Fatalf("%d ERROR records, want 1:\n%s", len(errs), allLogText(f))
	}
	if got, _ := recAttr(errs[0], "hash_id"); got != resp.HashID {
		t.Errorf("ERROR hash_id = %q, want %q", got, resp.HashID)
	}
	if got, _ := recAttr(errs[0], "error"); got != resp.PushError {
		t.Errorf("ERROR error = %q, want the pushError %q", got, resp.PushError)
	}
}

// F-1001-16 (geekdojo/geekdojo-brain#1001): a person who may set the password
// but may not run console.root_push (no nodes capability) still gets the 200
// the save earned, with the refusal's sentence as the push error, one WARN
// and the INFO change record; the password is stored and no job row exists.
func TestConsoleRootPassword_PutWhosePushIsRefusedKeepsTheSave(t *testing.T) {
	f := newAPIFixture(t)
	f.runner.Register(jobs.Workflow{Kind: console.PushKind})
	viewer := f.authenticateAs(t, "sub-vic", "vic", "viewer")

	w := f.do(t, http.MethodPut, "/api/console/root-password", `{"password":"`+testConsolePassword+`"}`, viewer)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s, want 200", w.Code, w.Body.String())
	}
	resp := decodeConsoleSet(t, w.Body.Bytes())
	const sentence = "You don't have permission to run this job."
	if resp.HashID == "" || resp.JobID != "" || resp.PushError != sentence {
		t.Fatalf("response = %+v, want a hashId, no jobId and pushError %q", resp, sentence)
	}
	g := f.do(t, http.MethodGet, "/api/console/root-password", "", f.authenticate(t))
	if st := decodeConsoleStatus(t, g.Body.Bytes()); !st.Set || st.HashID != resp.HashID {
		t.Fatalf("after the refused push the status is %+v, want the stored password %s", st, resp.HashID)
	}
	if got := f.rows(t, console.PushKind); len(got) != 0 {
		t.Errorf("%d %s rows, want none", len(got), console.PushKind)
	}
	warns := f.records(slog.LevelWarn, "console: the console root password was stored but the person may not run the job that applies it")
	if len(warns) != 1 {
		t.Fatalf("%d refusal WARN records, want 1:\n%s", len(warns), allLogText(f))
	}
	for key, want := range map[string]string{"hash_id": resp.HashID, "kind": console.PushKind, "code": "not_permitted"} {
		if got, _ := recAttr(warns[0], key); got != want {
			t.Errorf("WARN %s = %q, want %q", key, got, want)
		}
	}
	if n := len(f.records(slog.LevelError, "console: the console root password was stored but the job that applies it did not start")); n != 0 {
		t.Errorf("%d ERROR records for a refusal, want none", n)
	}
	info := f.records(slog.LevelInfo, "console: console root password set")
	if len(info) != 1 {
		t.Fatalf("%d INFO change records, want 1:\n%s", len(info), allLogText(f))
	}
	if got, _ := recAttr(info[0], "hash_id"); got != resp.HashID {
		t.Errorf("INFO hash_id = %q, want %q", got, resp.HashID)
	}
	if text := allLogText(f); strings.Contains(text, "sub-vic") || strings.Contains(text, testConsolePassword) {
		t.Errorf("the server log carries the person or the password:\n%s", text)
	}
}
