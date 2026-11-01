package secretstore_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-802-05: every store call made under a job carries X-Rasputin-Job-Id with
// the job's id; a call with no job id carries no such header at all. The
// header never changes a call's outcome: each call's result and error kind are
// the same in both runs, including a 403 that classifies as ErrDenied.
func TestClient_JobHeader(t *testing.T) {
	const jobID = "01JB802TESTJOBID0000000000"
	var mu sync.Mutex
	seen := map[string][]string{} // request "METHOD path" -> header values, per request
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		vals, present := r.Header[http.CanonicalHeaderKey(secretstore.JobHeader)]
		key := r.Method + " " + r.URL.Path
		if !present {
			vals = []string{"<absent>"}
		}
		seen[key] = append(seen[key], strings.Join(vals, ","))
		mu.Unlock()
		switch {
		case r.URL.Path == "/v1/auth/cert/login":
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "s.login"}})
		case strings.HasSuffix(r.URL.Path, "/denied"):
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
		case r.Method == http.MethodGet:
			writeJSON(w, 200, kvBody(1, map[string]any{"k": "v"}))
		case r.Method == http.MethodPost:
			writeJSON(w, 200, map[string]any{"data": map[string]any{"version": 1}})
		}
	})
	p := kvPath(t, "rasputin-secrets", "apps/x")
	denied := kvPath(t, "rasputin-secrets", "apps/denied")
	token := tok("s.api")

	type outcome struct{ read, write, login, deny string }
	kindOf := func(err error) string {
		for _, k := range []error{secretstore.ErrDenied, secretstore.ErrNotFound, secretstore.ErrProtocol, secretstore.ErrUnreachable} {
			if errors.Is(err, k) {
				return k.Error()
			}
		}
		if err != nil {
			return "other: " + err.Error()
		}
		return "ok"
	}
	run := func(ctx context.Context) outcome {
		kv, rErr := f.client.Read(ctx, token, p, 0)
		readOut := kindOf(rErr)
		if rErr == nil {
			readOut += " " + string(kv.Data["k"].Reveal())
		}
		v, wErr := f.client.Write(ctx, token, p, map[string]secret.Value{"k": tok("v")}, 0)
		lt, lErr := f.client.CertLogin(ctx, "rasputin-api")
		_, dErr := f.client.Read(ctx, token, denied, 0)
		return outcome{
			read:  readOut,
			write: kindOf(wErr) + " v" + strconv.Itoa(v),
			login: kindOf(lErr) + " " + string(lt.Reveal()),
			deny:  kindOf(dErr),
		}
	}

	stamped := run(jobs.ContextWithJobID(t.Context(), jobID))
	mu.Lock()
	stampedSeen := seen
	seen = map[string][]string{}
	mu.Unlock()
	plain := run(t.Context())
	mu.Lock()
	plainSeen := seen
	mu.Unlock()

	wantKeys := []string{
		"GET /v1/rasputin-secrets/data/apps/x",
		"POST /v1/rasputin-secrets/data/apps/x",
		"POST /v1/auth/cert/login",
		"GET /v1/rasputin-secrets/data/apps/denied",
	}
	for _, k := range wantKeys {
		if got := stampedSeen[k]; len(got) != 1 || got[0] != jobID {
			t.Errorf("under a job, %s carried %s %v, want exactly [%s]", k, secretstore.JobHeader, got, jobID)
		}
		if got := plainSeen[k]; len(got) != 1 || got[0] != "<absent>" {
			t.Errorf("with no job, %s carried %s %v, want the header absent", k, secretstore.JobHeader, got)
		}
	}
	if stamped != plain {
		t.Errorf("outcomes differ: under a job %+v, with no job %+v", stamped, plain)
	}
	if stamped.deny != secretstore.ErrDenied.Error() {
		t.Errorf("the 403 classified as %q, want ErrDenied", stamped.deny)
	}
	if stamped.read != "ok v" || stamped.login != "ok s.login" || stamped.write != "ok v1" {
		t.Errorf("stamped outcomes %+v, want each call to succeed", stamped)
	}
}
