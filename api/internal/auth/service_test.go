package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ============================================================================
// User WebAuthn methods
// ============================================================================

func TestUser_WebAuthnAccessors(t *testing.T) {
	u := &User{ID: []byte("xyz"), Name: "alice", DisplayName: "Alice"}
	if string(u.WebAuthnID()) != "xyz" {
		t.Error("WebAuthnID mismatch")
	}
	if u.WebAuthnName() != "alice" {
		t.Error("WebAuthnName mismatch")
	}
	if u.WebAuthnDisplayName() != "Alice" {
		t.Error("WebAuthnDisplayName mismatch")
	}
	if got := u.WebAuthnCredentials(); got != nil {
		t.Errorf("WebAuthnCredentials default: want nil, got %v", got)
	}
}

// ============================================================================
// publicUser / bytesToHex
// ============================================================================

// ============================================================================
// randomToken
// ============================================================================

// ============================================================================
// Pending store
// ============================================================================

// ============================================================================
// RequireSession / RequireSessionFunc
// ============================================================================

func TestRequireSession_MissingCookieReturns401(t *testing.T) {
	f := newAuthFixture(t)
	handler := f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestRequireSessionFunc_DelegatesToRequireSession(t *testing.T) {
	f := newAuthFixture(t)
	called := false
	wrapped := f.svc.RequireSessionFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	// No cookie → 401, downstream not called.
	w := httptest.NewRecorder()
	wrapped(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
	if called {
		t.Error("wrapped handler should not have been invoked")
	}
}

// ============================================================================
// Handler bad-input cases (don't need full WebAuthn)
// ============================================================================

// ============================================================================
// The authenticator choice on the wire (geekdojo/geekdojo-brain#586)
// ============================================================================

// ============================================================================
// NewService default-config behavior
// ============================================================================

func TestNewService_DefaultsAreApplied(t *testing.T) {
	f := newAuthFixture(t)
	// Re-create with empty config.
	svc, err := NewService(f.store, Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.cfg.RPDisplayName == "" {
		t.Error("RPDisplayName default not applied")
	}
	if svc.cfg.RPID == "" {
		t.Error("RPID default not applied")
	}
	if len(svc.cfg.RPOrigins) == 0 {
		t.Error("RPOrigins default not applied")
	}
}

// ============================================================================
// Start / Stop lifecycle (basic — no jitter)
// ============================================================================

func TestStart_Stop_NoPanic(t *testing.T) {
	f := newAuthFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.svc.Start(ctx)
	f.svc.Stop()
}

// ============================================================================
// LoginHook
// ============================================================================

func TestSetLoginHook_NoHookIsNoop(t *testing.T) {
	f := newAuthFixture(t)
	// Should not panic, should not block; with no hook installed there's
	// no observable effect, so the test asserts the negative (returns).
	f.svc.runLoginHook(context.Background(), "alice")
}

func TestSetLoginHook_FiresWithUserAndContext(t *testing.T) {
	f := newAuthFixture(t)
	type call struct {
		name string
		ctx  context.Context
	}
	got := make(chan call, 1)
	f.svc.SetLoginHook(func(ctx context.Context, name string) error {
		got <- call{name: name, ctx: ctx}
		return nil
	})

	// Use a distinctive ctx key so we can confirm the hook receives the
	// caller's context (not a fresh background one).
	type k int
	ctx := context.WithValue(context.Background(), k(0), "marker")
	f.svc.runLoginHook(ctx, "alice")

	select {
	case c := <-got:
		if c.name != "alice" {
			t.Errorf("hook name: got %q want alice", c.name)
		}
		if c.ctx.Value(k(0)) != "marker" {
			t.Errorf("hook did not receive caller context value")
		}
	case <-time.After(time.Second):
		t.Fatal("hook never fired")
	}
}

func TestSetLoginHook_ErrorDoesNotPropagate(t *testing.T) {
	f := newAuthFixture(t)
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error {
		return errors.New("downstream-down")
	})
	// runLoginHook returns nothing; the panic that this guards against is
	// the most important assertion.
	f.svc.runLoginHook(context.Background(), "alice")
}

func TestSetLoginHook_Replaceable(t *testing.T) {
	f := newAuthFixture(t)
	var aCount, bCount int
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error { aCount++; return nil })
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error { bCount++; return nil })
	f.svc.runLoginHook(context.Background(), "alice")
	if aCount != 0 {
		t.Errorf("replaced hook should not fire; aCount=%d", aCount)
	}
	if bCount != 1 {
		t.Errorf("replacement hook should fire exactly once; bCount=%d", bCount)
	}
}

func TestSetLoginHook_NilUninstalls(t *testing.T) {
	f := newAuthFixture(t)
	var fired bool
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error { fired = true; return nil })
	f.svc.SetLoginHook(nil)
	f.svc.runLoginHook(context.Background(), "alice")
	if fired {
		t.Error("nil SetLoginHook did not uninstall")
	}
}
