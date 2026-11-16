package idclient

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"testing"
)

// TC-979-20: Health asks /health/ready only and returns its report: the
// status and each check's name and status, with a 503's report beside its
// ErrUnreachable; a body that is not JSON and an unexpected status are
// ErrProtocol; its failure record is DEBUG. Disabled.Health refuses with its
// Kind and makes no call. Ready's own tests (client_test.go) are unchanged.
func TestHealth(t *testing.T) {
	p := newPKI(t)
	var mu sync.Mutex
	var paths []string
	var status int
	var body string
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		st, b := status, body
		mu.Unlock()
		w.WriteHeader(st)
		_, _ = w.Write([]byte(b))
	}, nil)
	c, rec := newClient(t, p, srv.URL)
	set := func(st int, b string) {
		mu.Lock()
		status, body = st, b
		mu.Unlock()
	}

	set(200, `{"status":"UP","checks":[{"name":"Keycloak database connections async health check","status":"UP"}]}`)
	rep, err := c.Health(t.Context())
	if err != nil || rep.Status != "UP" || len(rep.Checks) != 1 || rep.Checks[0].Status != "UP" ||
		rep.Down("Keycloak database connections async health check") {
		t.Fatalf("200: %+v, %v", rep, err)
	}

	set(503, `{"status":"DOWN","checks":[{"name":"Keycloak database connections async health check","status":"DOWN"}]}`)
	rep, err = c.Health(t.Context())
	var e *Error
	if !errors.Is(err, ErrUnreachable) || !errors.As(err, &e) || e.Status != 503 {
		t.Fatalf("503: err = %v, want ErrUnreachable with the status", err)
	}
	if !rep.Down("Keycloak database connections async health check") || rep.Down("another check") {
		t.Fatalf("503 report = %+v, want the database check DOWN", rep)
	}

	for _, c2 := range []struct {
		st   int
		body string
	}{{200, `not json`}, {404, `{}`}, {200, `{"status":"DOWN"}`}} {
		set(c2.st, c2.body)
		if _, err := c.Health(t.Context()); !errors.Is(err, ErrProtocol) {
			t.Errorf("%d %q: %v, want ErrProtocol", c2.st, c2.body, err)
		}
	}
	set(500, `not json`)
	if rep, err := c.Health(t.Context()); !errors.Is(err, ErrUnreachable) || len(rep.Checks) != 0 {
		t.Errorf("500 without the health JSON: %+v, %v", rep, err)
	}

	mu.Lock()
	for _, p := range paths {
		if p != "/health/ready" {
			t.Errorf("Health requested %s", p)
		}
	}
	mu.Unlock()
	if n := len(rec.AtLevel(slog.LevelWarn)) + len(rec.AtLevel(slog.LevelError)); n != 0 {
		t.Errorf("Health logged %d records above DEBUG, want none", n)
	}
	if n := len(rec.Matching(slog.LevelDebug, "identity service call failed")); n == 0 {
		t.Error("Health logged no DEBUG record for its failures")
	}

	before := srv.requests()
	if _, err := (Disabled{Kind: ErrMock}).Health(t.Context()); !errors.Is(err, ErrMock) {
		t.Fatalf("Disabled.Health = %v, want its Kind", err)
	}
	if srv.requests() != before {
		t.Fatal("Disabled.Health made a call")
	}
}
