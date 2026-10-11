package secretstore_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

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
	answers := map[string]kvAnswer{
		"200 value":  {status: 200, body: kvBody(1, map[string]any{"k": sentinelValue})},
		"403":        {status: 403, body: map[string]any{"errors": []string{storeMarker + " permission denied"}}},
		"404":        {status: 404, body: map[string]any{"errors": []string{storeMarker}}},
		"400 cas":    {status: 400, body: errs},
		"400 other":  {status: 400, body: map[string]any{"errors": []string{storeMarker + " bad"}}},
		"500":        {status: 500, body: map[string]any{"errors": []string{storeMarker + " internal"}}},
		"503 sealed": {status: 503, body: map[string]any{"errors": []string{storeMarker + " sealed"}}, health: healthAnswer(503, true, true)},
		"bad value":  {status: 200, body: kvBody(1, map[string]any{"k": 7, "v": sentinelValue})},
	}
	for name, a := range answers {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writeJSON(w, a.status, map[string]any{"errors": []string{storeMarker}, "data": map[string]any{"version": 1}})
					return
				}
				scripted(t, a)(w, r)
			})
			p := kvPath(t, "kv", "redact")
			var outs []any
			var gotErrs []error
			kv, err := f.client.Read(t.Context(), tok(sentinelToken), p, 0)
			outs = append(outs, kv)
			gotErrs = append(gotErrs, err)
			_, err = f.client.Write(t.Context(), tok(sentinelToken), p, map[string]secret.Value{"k": tok(sentinelValue)}, 0)
			gotErrs = append(gotErrs, err)
			_, err = f.client.Write(t.Context(), tok(sentinelToken), p, map[string]secret.Value{"k": tok(sentinelValue + "\xff")}, 0)
			gotErrs = append(gotErrs, err)
			md, err := f.client.Versions(t.Context(), tok(sentinelToken), p)
			outs = append(outs, md)
			gotErrs = append(gotErrs, err)
			assertRedacted(t, f.rec, outs, gotErrs)
		})
	}
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
