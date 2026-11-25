package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// fakeWaiting is the count the waiting route reads.
type fakeWaiting struct {
	n   int
	err error
}

func (w fakeWaiting) Count(context.Context) (int, error) { return w.n, w.err }

// codedBody is a coded refusal's body.
func codedBody(t *testing.T, body []byte) (code, msg string) {
	t.Helper()
	var b struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	return b.Code, b.Error
}

// TC-990-25: a person with no console role meets "An administrator needs
// to give you access." on a gated route, still coded route_not_permitted;
// a viewer on an admin route keeps the permission sentence. GET
// /api/accounts/waiting: 403 to a role-less person and a viewer, 200
// {"waiting":N} to an administrator, a coded 503 unwired, and a coded 500
// with no internal detail on a count error.
func TestWaiting_TC990_25(t *testing.T) {
	f := newAPIFixture(t)
	roleless := f.authenticateAs(t, "sub-b", "bob")
	viewer := f.authenticateAs(t, "sub-v", "val", "viewer")
	admin := f.authenticateAs(t, "sub-a", "alice", "admin")

	w := f.do(t, http.MethodGet, "/api/nodes", "", roleless)
	if code, msg := codedBody(t, w.Body.Bytes()); w.Code != http.StatusForbidden || code != codeRouteNotPermitted || msg != "An administrator needs to give you access." {
		t.Errorf("role-less on a gated route: %d %s %q", w.Code, code, msg)
	}
	w = f.do(t, http.MethodGet, "/api/accounts/waiting", "", viewer)
	if code, msg := codedBody(t, w.Body.Bytes()); w.Code != http.StatusForbidden || code != codeRouteNotPermitted || msg != "You don't have permission to do this." {
		t.Errorf("viewer on an admin route: %d %s %q", w.Code, code, msg)
	}
	if w := f.do(t, http.MethodGet, "/api/accounts/waiting", "", roleless); w.Code != http.StatusForbidden {
		t.Errorf("role-less on the waiting route: %d", w.Code)
	}

	w = f.do(t, http.MethodGet, "/api/accounts/waiting", "", admin)
	if code, _ := codedBody(t, w.Body.Bytes()); w.Code != http.StatusServiceUnavailable || code != codeIdentityNotReady {
		t.Errorf("unwired: %d %s", w.Code, code)
	}
	f.srv.SetWaiting(fakeWaiting{n: 7})
	w = f.do(t, http.MethodGet, "/api/accounts/waiting", "", admin)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"waiting":7}` {
		t.Errorf("wired: %d %s", w.Code, w.Body.String())
	}
	f.srv.SetWaiting(fakeWaiting{err: errors.New("GET /admin/realms/rasputin/users: secret-detail")})
	w = f.do(t, http.MethodGet, "/api/accounts/waiting", "", admin)
	if code, _ := codedBody(t, w.Body.Bytes()); w.Code != http.StatusInternalServerError || code != codeWaitingUnavailable {
		t.Errorf("a count error: %d %s", w.Code, code)
	}
	if strings.Contains(w.Body.String(), "secret-detail") || strings.Contains(w.Body.String(), "/admin/") {
		t.Errorf("the body carries the internal error: %s", w.Body.String())
	}
}

// claimDesignator writes nothing: the restore tests need only the claim.
type claimDesignator struct{}

func (claimDesignator) DesignateFirstAdmin(context.Context, *sql.Tx, string) error { return nil }

// TC-990-04 (api half) and C03: a first-run claim alone, with no
// pre-update operator, closes the restore surface, and status says
// firstRun:false.
func TestRestore_TC990_04_ClaimClosesTheSurface(t *testing.T) {
	rf := newRestoreFixture(t)
	if w := rf.do(t, http.MethodGet, "/api/restore/candidates", nil); w.Code != http.StatusOK {
		t.Fatalf("a fresh box: %d", w.Code)
	}
	cs, err := auth.NewConsoleSessions(rf.authStore, time.Now, rand.Reader, claimDesignator{})
	if err != nil {
		t.Fatal(err)
	}
	c, claimed, err := cs.CreateWithClaim(rf.ctx, auth.Principal{Sub: "a", Session: auth.SessionRef{SID: "s"}}, &auth.Claim{Sub: "a"})
	if err != nil || !claimed {
		t.Fatalf("the claim: %v %v", claimed, err)
	}
	c.Destroy()
	if w := rf.do(t, http.MethodGet, "/api/restore/candidates", nil); w.Code != http.StatusConflict {
		t.Errorf("candidates after the claim: %d %s", w.Code, w.Body.String())
	}
	w := rf.do(t, http.MethodPost, "/api/restore", map[string]string{
		"partUuid": rtPartUUID, "generationId": rf.genID, "keyId": rtKeyID, "privateKey": rf.privB64(),
	})
	if w.Code != http.StatusConflict || rf.restarts.Load() != 0 {
		t.Errorf("restore phase 1 after the claim: %d", w.Code)
	}
	w = rf.do(t, http.MethodGet, "/api/auth/status", nil)
	if !strings.Contains(w.Body.String(), `"firstRun":false`) {
		t.Errorf("status after the claim: %s", w.Body.String())
	}
}
