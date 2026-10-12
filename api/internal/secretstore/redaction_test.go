package secretstore_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	sentinelToken = "SENTINEL-TOKEN-7c1f"
	sentinelValue = "SENTINEL-VALUE-93ab"
	storeMarker   = "STORE-MESSAGE-MARKER-55d0"
)

// TC-758-13: no token or value reaches a log record, an error's rendering,
// StoreMessages, LogAttrs or JSON, across every outcome of TC-758-05 to
// TC-758-09. The store's own text reaches the log and LogAttrs, and never
// Error().
func TestRedaction(t *testing.T) {
	errs := map[string]any{"errors": []string{storeMarker + " check-and-set parameter did not match the current version"}}
	// kv answers a KV GET with a, and a write with a's status.
	kv := func(a kvAnswer) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				writeJSON(w, a.status, map[string]any{"errors": []string{storeMarker}, "data": map[string]any{"version": 1}})
				return
			}
			scripted(t, a)(w, r)
		}
	}
	// raw answers every request with body as it stands.
	raw := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	gone := func(field string, v any) map[string]any {
		b := kvBody(2, map[string]any{"k": sentinelValue})
		b["data"].(map[string]any)["metadata"].(map[string]any)[field] = v
		return b
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	redirect := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", target.URL+"/steal")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, sentinelValue)
		}
	}
	answers := map[string]http.HandlerFunc{
		"200 value":      kv(kvAnswer{status: 200, body: kvBody(1, map[string]any{"k": sentinelValue})}),
		"403":            kv(kvAnswer{status: 403, body: map[string]any{"errors": []string{storeMarker + " permission denied"}}}),
		"404":            kv(kvAnswer{status: 404, body: map[string]any{"errors": []string{storeMarker}}}),
		"400 cas":        kv(kvAnswer{status: 400, body: errs}),
		"400 other":      kv(kvAnswer{status: 400, body: map[string]any{"errors": []string{storeMarker + " bad"}}}),
		"500":            kv(kvAnswer{status: 500, body: map[string]any{"errors": []string{storeMarker + " internal"}}}),
		"503 sealed":     kv(kvAnswer{status: 503, body: map[string]any{"errors": []string{storeMarker + " sealed"}}, health: healthAnswer(503, true, true)}),
		"bad value":      kv(kvAnswer{status: 200, body: kvBody(1, map[string]any{"k": 7, "v": sentinelValue})}),
		"deleted":        kv(kvAnswer{status: 200, body: gone("deletion_time", "2026-10-11T10:00:00Z")}),
		"destroyed":      kv(kvAnswer{status: 200, body: gone("destroyed", true)}),
		"malformed JSON": raw(200, `{"data":{"data":{"k":"`+sentinelValue),
		"over 1 MiB":     raw(200, `{"data":{"data":{"k":"`+sentinelValue+strings.Repeat("x", 1<<20)+`"}}}`),
		"302":            redirect(http.StatusFound),
		"307":            redirect(http.StatusTemporaryRedirect),
	}
	for name, h := range answers {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, h)
			outs, gotErrs := callEveryKVMethod(t, f.client)
			assertRedacted(t, f.rec, outs, gotErrs)
		})
	}
}

// callEveryKVMethod makes each KV call with the sentinel token, and writes
// the sentinel value, and returns what came back.
func callEveryKVMethod(t *testing.T, c *secretstore.Client) (outs []any, errs []error) {
	t.Helper()
	p := kvPath(t, "kv", "redact")
	kv, err := c.Read(t.Context(), tok(sentinelToken), p, 0)
	outs = append(outs, kv)
	errs = append(errs, err)
	_, err = c.Write(t.Context(), tok(sentinelToken), p, map[string]secret.Value{"k": tok(sentinelValue)}, 0)
	errs = append(errs, err)
	_, err = c.Write(t.Context(), tok(sentinelToken), p, map[string]secret.Value{"k": tok(sentinelValue + "\xff")}, 0)
	errs = append(errs, err)
	md, err := c.Versions(t.Context(), tok(sentinelToken), p)
	outs = append(outs, md)
	errs = append(errs, err)
	return outs, errs
}

// TC-758-13 over TC-758-06 and TC-758-07: the Health outcomes, with the
// sentinel in the body, and the transport failures, with the sentinel token
// and value in the call.
func TestRedaction_HealthAndTransport(t *testing.T) {
	for _, status := range []int{200, 501, 503, 429, 472, 473} {
		for _, sealed := range []bool{false, true} {
			t.Run(fmt.Sprintf("health %d sealed=%t", status, sealed), func(t *testing.T) {
				f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, status, map[string]any{"initialized": status != 501, "sealed": sealed,
						"version": "2.7.1", "errors": []string{storeMarker}, "cluster_name": sentinelValue})
				})
				h, err := f.client.Health(t.Context())
				assertRedacted(t, f.rec, []any{h}, []error{err})
			})
		}
	}
	t.Run("health malformed JSON", func(t *testing.T) {
		f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"initialized":true,"x":"`+sentinelValue)
		})
		h, err := f.client.Health(t.Context())
		assertRedacted(t, f.rec, []any{h}, []error{err})
	})

	// stall reads the request whole, so the server notices the client hang
	// up, and then answers nothing.
	stall := func(r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}
	t.Run("call bound runs out", func(t *testing.T) {
		f := newFixture(t, func(_ http.ResponseWriter, r *http.Request) { stall(r) })
		lg, rec := logkittest.New()
		u, _ := secretstore.ParseAddr(f.srv.URL)
		c, err := secretstore.New(secretstore.Config{Addr: u, TLS: mustTLS(t, f.ca.CertPEM, f.leaf), CallTimeout: 100 * time.Millisecond, Logger: lg})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.CloseIdleConnections)
		outs, errs := callEveryKVMethod(t, c)
		assertRedacted(t, rec, outs, errs)
	})
	t.Run("caller cancels", func(t *testing.T) {
		arrived := make(chan struct{}, 1)
		f := newFixture(t, func(_ http.ResponseWriter, r *http.Request) {
			arrived <- struct{}{}
			stall(r)
		})
		p := kvPath(t, "kv", "redact")
		var outs []any
		var errs []error
		for _, call := range []func(ctx context.Context) (any, error){
			func(ctx context.Context) (any, error) { return f.client.Read(ctx, tok(sentinelToken), p, 0) },
			func(ctx context.Context) (any, error) {
				return f.client.Write(ctx, tok(sentinelToken), p, map[string]secret.Value{"k": tok(sentinelValue)}, 0)
			},
			func(ctx context.Context) (any, error) { return f.client.Versions(ctx, tok(sentinelToken), p) },
		} {
			ctx, cancel := context.WithCancel(t.Context())
			go func() {
				select {
				case <-arrived:
					cancel()
				case <-ctx.Done():
				}
			}()
			out, err := call(ctx)
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want context.Canceled", err)
			}
			outs, errs = append(outs, out), append(errs, err)
		}
		assertRedacted(t, f.rec, outs, errs)
	})
	t.Run("client certificate refused", func(t *testing.T) {
		ca, foreign := storeCA(t), storeCA(t)
		srv := startTLSServer(t, serverCert(t, ca), ca, tls.VersionTLS13, tls.VersionTLS13, okHandler())
		lg, rec := logkittest.New()
		c := newClient(t, srv.URL, mustTLS(t, ca.CertPEM, clientLeaf(t, foreign)), lg)
		outs, errs := callEveryKVMethod(t, c)
		assertRedacted(t, rec, outs, errs)
	})
}

// assertRedacted scans everything a caller or an operator could see for the
// sentinel token and value, and for any extra secret text.
func assertRedacted(t *testing.T, rec *logkittest.Recorder, outs []any, errs []error, extra ...string) {
	t.Helper()
	var seen []string
	for _, o := range outs {
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, string(b), fmt.Sprintf("%v", o), fmt.Sprintf("%+v", o), fmt.Sprintf("%#v", o))
	}
	for _, err := range errs {
		if err == nil {
			continue
		}
		rendered := []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)}
		seen = append(seen, rendered...)
		for _, r := range rendered {
			if strings.Contains(r, storeMarker) {
				t.Errorf("the store's message reached the error rendering: %s", r)
			}
		}
		var se *secretstore.Error
		if errors.As(err, &se) {
			seen = append(seen, strings.Join(se.StoreMessages, "|"), attrsText(se.LogAttrs()))
		}
	}
	seen = append(seen, rec.Text())
	for _, s := range seen {
		for _, secretText := range append([]string{sentinelToken, sentinelValue}, extra...) {
			if strings.Contains(s, secretText) {
				t.Errorf("a sentinel leaked: %s", s)
			}
		}
	}
}

func attrsText(attrs []slog.Attr) string {
	var b strings.Builder
	for _, a := range attrs {
		fmt.Fprintf(&b, "%s=%v ", a.Key, a.Value.Resolve().Any())
	}
	return b.String()
}

// TC-758-13 (store text) and TC-758-14: one client record per failed call,
// with every field and the level its kind calls for; and the caller's own
// record, built from LogAttrs, holds its correlation id and the store's
// messages together.
func TestLogRecords(t *testing.T) {
	errs := func(m string) map[string]any { return map[string]any{"errors": []string{storeMarker + " " + m}} }
	for _, tc := range []struct {
		name  string
		a     kvAnswer
		kind  string
		level slog.Level
	}{
		{"not found", kvAnswer{status: 404, body: errs("")}, "not found", slog.LevelDebug},
		{"cas", kvAnswer{status: 400, body: errs("check-and-set parameter did not match the current version")}, "check-and-set mismatch", slog.LevelDebug},
		{"denied", kvAnswer{status: 403, body: errs("permission denied")}, "denied", slog.LevelWarn},
		{"sealed", kvAnswer{status: 503, body: errs("sealed"), health: healthAnswer(503, true, true)}, "sealed", slog.LevelWarn},
		{"uninitialised", kvAnswer{status: 503, body: errs("x"), health: healthAnswer(501, false, true)}, "uninitialised", slog.LevelWarn},
		{"unreachable", kvAnswer{status: 502, body: errs("x")}, "unreachable", slog.LevelWarn},
		{"protocol", kvAnswer{status: 400, body: errs("bad")}, "protocol error", slog.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, scripted(t, tc.a))
			_, err := f.client.Read(t.Context(), tok("t"), kvPath(t, "kv", "logged"), 0)
			recs := f.rec.Records()
			if len(recs) != 1 {
				t.Fatalf("%d records, want exactly 1", len(recs))
			}
			r := recs[0]
			if r.Level != tc.level {
				t.Errorf("level = %v, want %v", r.Level, tc.level)
			}
			for key, want := range map[string]string{
				"component": "secretstore", "op": "read", "mount": "kv", "path": "logged",
				"status": fmt.Sprint(tc.a.status), "kind": tc.kind,
			} {
				if got, ok := logkittest.Attr(r, key); !ok || got != want {
					t.Errorf("%s = %q (present %t), want %q", key, got, ok, want)
				}
			}
			if msgs, _ := logkittest.Attr(r, "store_messages"); !strings.Contains(msgs, storeMarker) {
				t.Errorf("store_messages = %q, want the store's text", msgs)
			}
			if strings.Contains(err.Error(), storeMarker) {
				t.Errorf("Error() = %q carries the store's text", err)
			}

			// The caller's record (F-758-06).
			var se *secretstore.Error
			if !errors.As(err, &se) {
				t.Fatal("not an *Error")
			}
			callerLog, callerRec := logkittest.New()
			callerLog.LogAttrs(t.Context(), slog.LevelWarn, "request failed",
				append([]slog.Attr{slog.String("correlation_id", "req-42")}, se.LogAttrs()...)...)
			cr := callerRec.Records()[0]
			cid, _ := logkittest.Attr(cr, "correlation_id")
			msgs, _ := logkittest.Attr(cr, "store_messages")
			if cid != "req-42" || !strings.Contains(msgs, storeMarker) {
				t.Errorf("caller record correlation_id %q store_messages %q, want both in one record", cid, msgs)
			}
		})
	}
}

// TC-760-21: a Health call that finds the store sealed, uninitialised or
// unreachable is recorded at DEBUG, because its callers log that outcome
// themselves; a protocol error stays ERROR. TestLogRecords above keeps the KV
// levels unchanged.
func TestHealthLogLevels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		health func(http.ResponseWriter)
		kind   string
		level  slog.Level
	}{
		{"sealed", healthAnswer(503, true, true), "sealed", slog.LevelDebug},
		{"uninitialised", healthAnswer(501, false, true), "uninitialised", slog.LevelDebug},
		{"unreachable", hangUp, "unreachable", slog.LevelDebug},
		{"protocol", healthAnswer(200, true, true), "protocol error", slog.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, scripted(t, kvAnswer{health: tc.health}))
			if _, err := f.client.Health(t.Context()); err == nil {
				t.Fatal("Health succeeded")
			}
			recs := f.rec.Records()
			if len(recs) != 1 {
				t.Fatalf("%d records, want exactly 1", len(recs))
			}
			if recs[0].Level != tc.level {
				t.Errorf("level = %v, want %v", recs[0].Level, tc.level)
			}
			if got, _ := logkittest.Attr(recs[0], "kind"); got != tc.kind {
				t.Errorf("kind = %q, want %q", got, tc.kind)
			}
		})
	}
}
