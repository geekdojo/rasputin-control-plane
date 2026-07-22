package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

func bmcTestSetupStore(t *testing.T) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatalf("setup store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSanitizeBMCConfig(t *testing.T) {
	// Non-bitscope passes through untouched.
	if got := sanitizeBMCConfig("mock", `{"targets":["a"]}`); string(got) != `{"targets":["a"]}` {
		t.Errorf("mock passthrough: %s", got)
	}
	// Legacy bitscope config with an embedded unlock: stripped + marked.
	got := sanitizeBMCConfig("bitscope", `{"dev":"/dev/serial0","unlock":"sekrit"}`)
	if strings.Contains(string(got), "sekrit") {
		t.Fatalf("unlock leaked: %s", got)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["unlockSet"] != true || m["dev"] != "/dev/serial0" {
		t.Errorf("sanitized: %v", m)
	}
	// Garbage never leaks raw bytes back.
	if got := sanitizeBMCConfig("bitscope", "not-json"); got != nil {
		t.Errorf("garbage: %s", got)
	}
}

func TestSetUnlockSet(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(setUnlockSet(json.RawMessage(`{"dev":"x"}`)), &m); err != nil {
		t.Fatal(err)
	}
	if m["unlockSet"] != true || m["dev"] != "x" {
		t.Errorf("annotate: %v", m)
	}
	if err := json.Unmarshal(setUnlockSet(nil), &m); err != nil {
		t.Fatal(err)
	}
	if m["unlockSet"] != true {
		t.Errorf("annotate empty: %v", m)
	}
}

func TestStoreAndStripUnlock(t *testing.T) {
	ctx := context.Background()
	st := bmcTestSetupStore(t)

	// A typed unlock lands in its own key and never in the returned blob.
	out, err := storeAndStripUnlock(ctx, st, json.RawMessage(`{"dev":"/d","unlock":"newsecret","targets":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "newsecret") || strings.Contains(string(out), "unlock") {
		t.Fatalf("secret/field leaked into job-safe config: %s", out)
	}
	if v, _ := st.Get(ctx, setup.KeyBMCBitscopeUnlock); v != "newsecret" {
		t.Errorf("stored unlock: %q", v)
	}

	// Empty unlock keeps the stored secret.
	if _, err := storeAndStripUnlock(ctx, st, json.RawMessage(`{"dev":"/d","unlock":"","unlockSet":true}`)); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.Get(ctx, setup.KeyBMCBitscopeUnlock); v != "newsecret" {
		t.Errorf("empty unlock must keep stored secret, got %q", v)
	}

	// Bad JSON errors rather than passing through.
	if _, err := storeAndStripUnlock(ctx, st, json.RawMessage(`nope`)); err == nil {
		t.Error("bad json must error")
	}
}
