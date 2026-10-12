package secretstoretest

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-760-24: against the real pinned store, Stop leaves the process exited
// and the data dir in place; Restart returns once sys/health is 200 unsealed,
// with the KV written before the stop read back unchanged; RestartSealed
// still ends on 503 sealed; and Close afterwards leaves no process and no
// temporary directory (geekdojo/geekdojo-brain#760).
func TestSecretStore_StopAndRestartKeepData(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	parent := t.TempDir()
	h, err := New(Config{BinaryPath: bin, TempParent: parent, Logger: logger, Now: time.Now, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = s.Close(context.Background())
		}
	})

	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	client, err := secretstore.New(secretstore.Config{Addr: u, TLS: s.ClientTLS(), CallTimeout: 10 * time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	p, err := secretstore.NewKVPath(KVMount, "restart/kept")
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(t.Context(), token, p, map[string]secret.Value{"k": secret.New([]byte("kept-value"))}, 0); err != nil {
		t.Fatal(err)
	}

	firstPID := s.cmd.Process.Pid
	if err := s.Stop(t.Context()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := syscall.Kill(firstPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("kill -0 %d after Stop = %v, want ESRCH", firstPID, err)
	}
	if _, err := os.Stat(s.root); err != nil {
		t.Fatalf("the data dir is gone after Stop: %v", err)
	}
	if _, err := client.Health(t.Context()); !errors.Is(err, secretstore.ErrUnreachable) {
		t.Fatalf("Health after Stop = %v, want ErrUnreachable", err)
	}

	if err := s.Restart(t.Context()); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if h, err := client.Health(t.Context()); err != nil || !h.Initialized || h.Sealed {
		t.Fatalf("Health after Restart = (%+v, %v), want 200 initialised and unsealed", h, err)
	}
	token2, err := s.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	kv, err := client.Read(t.Context(), token2, p, 0)
	if err != nil {
		t.Fatalf("Read after Restart: %v", err)
	}
	if got := string(kv.Data["k"].Reveal()); got != "kept-value" || kv.Version != 1 {
		t.Fatalf("Read after Restart = %q at version %d, want kept-value at 1", got, kv.Version)
	}
	kv.Destroy()

	if err := s.RestartSealed(t.Context()); err != nil {
		t.Fatalf("RestartSealed after Restart: %v", err)
	}
	if _, err := client.Health(t.Context()); !errors.Is(err, secretstore.ErrSealed) {
		t.Fatalf("Health after RestartSealed = %v, want ErrSealed", err)
	}

	lastPID := s.cmd.Process.Pid
	closed = true
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertReaped(t, lastPID)
	assertEmpty(t, parent)
}
