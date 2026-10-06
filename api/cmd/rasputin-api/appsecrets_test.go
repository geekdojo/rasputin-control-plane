package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit"
)

// attr returns the named attribute of r as a string, and whether it was set.
func attr(r slog.Record, key string) (string, bool) {
	var v string
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v, found = a.Value.String(), true
			return false
		}
		return true
	})
	return v, found
}

// TC-692-13: a seed file that does not parse is one FATAL record, with the
// path and the error, and exactly one exit(1); nothing is returned and no
// "loaded" record is written.
func TestLoadAppSecrets_UnreadableSeedIsFatal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")
	if err := atrest.EnsureSecretDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, appsecret.SeedFileName)
	if err := atrest.WriteSecretFile(path, []byte("this is not a seed file\n")); err != nil {
		t.Fatal(err)
	}
	h := &recordsHandler{}
	var codes []int

	seed, src := loadAppSecrets(context.Background(), slog.New(h), func(code int) { codes = append(codes, code) }, dir)

	if len(codes) != 1 || codes[0] != 1 {
		t.Fatalf("exit calls %v, want exactly one exit(1)", codes)
	}
	if seed != nil || src != nil {
		t.Fatalf("returned seed %v and source %v after a failed load, want nil, nil", seed, src)
	}
	fatal := h.matching(logkit.LevelFatal, "rasputin-api: app-secret seed did not load")
	if len(fatal) != 1 {
		t.Fatalf("%d FATAL seed records, want 1", len(fatal))
	}
	if got, _ := attr(fatal[0], "path"); got != path {
		t.Errorf("FATAL record path=%q, want %q", got, path)
	}
	if got, _ := attr(fatal[0], "err"); got == "" {
		t.Error("FATAL record carries no err")
	}
	if n := len(h.matching(slog.LevelInfo, "seed loaded")); n != 0 {
		t.Errorf("%d seed-loaded records after a failed load, want 0", n)
	}
}

// TC-692-14: a first start mints the seed and logs one INFO record with the
// path and the derivation version, not FATAL, and no exit; a second start
// over that file logs nothing of the key.
func TestLoadAppSecrets_LoadedIsInfoWithoutTheSeed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")
	path := filepath.Join(dir, appsecret.SeedFileName)
	exited := false
	exit := func(int) { exited = true }

	h := &recordsHandler{}
	seed, src := loadAppSecrets(context.Background(), slog.New(h), exit, dir)
	if exited {
		t.Fatal("loadAppSecrets exited although the seed loaded")
	}
	if seed == nil || src == nil {
		t.Fatalf("returned seed %v and source %v, want both non-nil", seed, src)
	}
	if n := len(h.matching(logkit.LevelFatal, "")); n != 0 {
		t.Fatalf("%d FATAL records although the seed loaded, want 0", n)
	}
	info := h.matching(slog.LevelInfo, "rasputin-api: app-secret seed loaded")
	if len(info) != 1 {
		t.Fatalf("%d seed-loaded INFO records, want 1", len(info))
	}
	if got, _ := attr(info[0], "path"); got != path {
		t.Errorf("INFO record path=%q, want %q", got, path)
	}
	if got, ok := attr(info[0], "derivation_version"); !ok || got != "1" || appsecret.DerivationVersion != 1 {
		t.Errorf("INFO record derivation_version=%q (set %v), want %d", got, ok, appsecret.DerivationVersion)
	}

	// The second start reads the file the first one wrote; no attribute of its
	// record may carry the key text.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw))
	key := fields[len(fields)-1]
	if len(key) < 40 {
		t.Fatalf("could not find the base64 key in the seed file (last field %q)", key)
	}
	h2 := &recordsHandler{}
	if seed, src := loadAppSecrets(context.Background(), slog.New(h2), exit, dir); seed == nil || src == nil || exited {
		t.Fatal("the second start did not load the seed the first one wrote")
	}
	info = h2.matching(slog.LevelInfo, "rasputin-api: app-secret seed loaded")
	if len(info) != 1 {
		t.Fatalf("%d seed-loaded INFO records on the second start, want 1", len(info))
	}
	if strings.Contains(info[0].Message, key) {
		t.Error("the seed-loaded message carries the key")
	}
	info[0].Attrs(func(a slog.Attr) bool {
		if strings.Contains(a.Value.String(), key) {
			t.Errorf("attribute %s carries the key", a.Key)
		}
		return true
	})
}

// TC-692-03: a constructor that refused its wiring is one FATAL record with
// its error and exactly one exit(1); one that did not is passed through with
// no record and no exit.
func TestWorkflowOrExit(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		h := &recordsHandler{}
		var codes []int
		must := workflowOrExit(context.Background(), slog.New(h), func(code int) { codes = append(codes, code) })
		refusal := errors.New("apps: app.deploy workflow: a secret source is required")

		w := must(jobs.Workflow{}, refusal)

		if len(codes) != 1 || codes[0] != 1 {
			t.Fatalf("exit calls %v, want exactly one exit(1)", codes)
		}
		if w.Kind != "" || len(w.Steps) != 0 {
			t.Fatalf("returned %+v after a refusal, want the zero workflow", w)
		}
		fatal := h.matching(logkit.LevelFatal, "rasputin-api: app workflow refused its wiring")
		if len(fatal) != 1 || len(h.recs) != 1 {
			t.Fatalf("%d FATAL records of %d, want exactly 1", len(fatal), len(h.recs))
		}
		if got, _ := attr(fatal[0], "err"); got != refusal.Error() {
			t.Fatalf("FATAL record err=%q, want %q", got, refusal.Error())
		}
	})
	t.Run("accepted", func(t *testing.T) {
		h := &recordsHandler{}
		exited := false
		must := workflowOrExit(context.Background(), slog.New(h), func(int) { exited = true })
		in := jobs.Workflow{Kind: "app.deploy", Steps: []jobs.WorkflowStep{{Name: "push", Timeout: time.Second}}}

		w := must(in, nil)

		if exited {
			t.Fatal("exited although the constructor accepted its wiring")
		}
		if w.Kind != in.Kind || len(w.Steps) != 1 || w.Steps[0].Name != "push" {
			t.Fatalf("returned %+v, want the workflow unchanged", w)
		}
		if len(h.recs) != 0 {
			t.Fatalf("%d records written, want none", len(h.recs))
		}
	})
}
