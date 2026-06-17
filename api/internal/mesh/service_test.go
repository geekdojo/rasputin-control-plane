package mesh

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// stubClient is a minimal Client for Service tests.
type stubClient struct {
	backend     string
	ensureCalls int32
}

func (s *stubClient) Backend() string { return s.backend }
func (s *stubClient) EnsureUser(context.Context, string) error {
	atomic.AddInt32(&s.ensureCalls, 1)
	return nil
}
func (s *stubClient) CreatePreAuthKey(context.Context, CreatePreAuthKeyInput) (string, string, error) {
	return "id", "key", nil
}
func (s *stubClient) ExpirePreAuthKey(context.Context, string) error { return nil }
func (s *stubClient) ListPreAuthKeys(context.Context, string) ([]HSPreAuthKey, error) {
	return nil, nil
}
func (s *stubClient) ListNodes(context.Context) ([]HSNode, error)           { return nil, nil }
func (s *stubClient) SetNodeRoutes(context.Context, string, []string) error { return nil }
func (s *stubClient) DeleteNode(context.Context, string) error              { return nil }

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

// Self-hosted: Start runs the bootstrap in the background and swaps the
// placeholder client for the real one, then ensures the default user.
func TestService_BackgroundBootstrapSwapsClient(t *testing.T) {
	real := &stubClient{backend: "headscale-real"}
	svc := NewService(Config{DefaultUser: "op"}, nil, NewNotReadyClient("headscale"), NewNoopSupervisor())
	svc.SetBootstrap(func(context.Context) (Client, error) { return real, nil })

	// Before Start: placeholder, ops fail fast.
	if svc.Client().Backend() != "headscale" {
		t.Fatalf("pre-start backend = %q, want placeholder 'headscale'", svc.Client().Backend())
	}
	if _, _, err := svc.Client().CreatePreAuthKey(context.Background(), CreatePreAuthKeyInput{}); err != ErrMeshNotReady {
		t.Fatalf("placeholder should return ErrMeshNotReady, got %v", err)
	}

	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool { return svc.Client().Backend() == "headscale-real" }, "client swap")
	waitFor(t, func() bool { return atomic.LoadInt32(&real.ensureCalls) >= 1 }, "EnsureUser called")
}

// Start must return immediately even if bring-up blocks — the api can't wait
// on Headscale to answer /healthz.
func TestService_StartDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	real := &stubClient{backend: "headscale-real"}
	svc := NewService(Config{DefaultUser: "op"}, nil, NewNotReadyClient("headscale"), NewNoopSupervisor())
	svc.SetBootstrap(func(ctx context.Context) (Client, error) {
		<-release // simulate a slow container bring-up
		return real, nil
	})

	done := make(chan struct{})
	go func() { _ = svc.Start(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start blocked on bring-up")
	}
	// Still on the placeholder while bring-up is stuck.
	if svc.Client().Backend() != "headscale" {
		t.Fatalf("expected placeholder while blocked, got %q", svc.Client().Backend())
	}
	close(release)
	waitFor(t, func() bool { return svc.Client().Backend() == "headscale-real" }, "swap after unblock")
}

// Eager mode (mock/external): no bootstrap; Start just ensures the user in the
// background, client unchanged.
func TestService_EagerModeEnsuresUser(t *testing.T) {
	c := &stubClient{backend: "mock"}
	svc := NewService(Config{DefaultUser: "op"}, nil, c, NewNoopSupervisor())
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, func() bool { return atomic.LoadInt32(&c.ensureCalls) >= 1 }, "EnsureUser called")
	if svc.Client().Backend() != "mock" {
		t.Fatalf("eager client should be unchanged, got %q", svc.Client().Backend())
	}
}
