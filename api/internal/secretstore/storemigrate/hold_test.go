package storemigrate

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// blockingSession is a kv and key session whose Write blocks until release
// is closed, after closing entered; every other call returns at once.
type blockingSession struct {
	entered chan struct{}
	release chan struct{}
	reached int
}

func (b *blockingSession) Read(context.Context, secretstore.KVPath, int) (secretstore.KV, error) {
	b.reached++
	return secretstore.KV{}, nil
}

func (b *blockingSession) Write(context.Context, secretstore.KVPath, map[string]secret.Value, int) (int, error) {
	close(b.entered)
	<-b.release
	return 1, nil
}

func (b *blockingSession) Versions(context.Context, secretstore.KVPath) (secretstore.Metadata, error) {
	b.reached++
	return secretstore.Metadata{}, nil
}

func (b *blockingSession) Delete(context.Context, secretstore.KVPath) error { b.reached++; return nil }

func (b *blockingSession) TransitCreateKey(context.Context, secretstore.TransitKey) error {
	b.reached++
	return nil
}

func (b *blockingSession) TransitEncrypt(context.Context, secretstore.TransitKey, secret.Value) (secret.Value, error) {
	b.reached++
	return secret.Value{}, nil
}

func (b *blockingSession) TransitDecrypt(context.Context, secretstore.TransitKey, secret.Value) (secret.Value, error) {
	b.reached++
	return secret.Value{}, nil
}

func (b *blockingSession) TransitDestroyKey(context.Context, secretstore.TransitKey) error {
	b.reached++
	return nil
}

// noFiles is a state directory holding nothing.
type noFiles struct{}

func (noFiles) Present(string) (bool, error) { return false, nil }

// isQuiesced reports whether err is the Hold's refusal.
func isQuiesced(err error) bool {
	var nr *storestate.NotReadyError
	return errors.As(err, &nr) && nr.State == storestate.Quiesced
}

// TC-1132-20 (F-1132-03, F-1132-08): On returns only after a Write already
// inside the session returns. While held, every kv and Transit call is
// refused with NotReadyError{Quiesced} and never reaches the session. After
// Off, calls pass through. Ordering is asserted through channels and the
// refusal fact, never a timer.
func TestHold(t *testing.T) {
	ctx := context.Background()
	h, err := NewHold(noFiles{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s := &blockingSession{entered: make(chan struct{}), release: make(chan struct{})}
	kv, tr := h.KV(s), h.Transit(s)
	p, err := secretstore.NewKVPath("rasputin-secrets", "apps/x/y")
	if err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		if _, err := kv.Write(ctx, p, nil, 0); err != nil {
			t.Errorf("in-flight write: %v", err)
		}
	}()
	<-s.entered
	onDone := make(chan struct{})
	go func() { h.On(); close(onDone) }()
	// The fact that On is waiting: a new call is refused.
	for {
		if _, err := kv.Read(ctx, p, 0); isQuiesced(err) {
			break
		}
		runtime.Gosched()
	}
	select {
	case <-onDone:
		t.Fatal("On returned while a write was still inside the session")
	default:
	}
	close(s.release)
	<-writeDone
	<-onDone

	s.reached = 0
	key := secretstore.TransitKey{}
	refusals := []error{
		func() error { _, err := kv.Read(ctx, p, 0); return err }(),
		func() error { _, err := kv.Write(ctx, p, nil, 0); return err }(),
		func() error { _, err := kv.Versions(ctx, p); return err }(),
		kv.Delete(ctx, p),
		tr.TransitCreateKey(ctx, key),
		func() error { _, err := tr.TransitEncrypt(ctx, key, secret.Value{}); return err }(),
		func() error { _, err := tr.TransitDecrypt(ctx, key, secret.Value{}); return err }(),
		tr.TransitDestroyKey(ctx, key),
	}
	for i, err := range refusals {
		if !isQuiesced(err) {
			t.Errorf("call %d while held: %v, want NotReadyError{Quiesced}", i, err)
		}
	}
	if s.reached != 0 {
		t.Fatalf("%d held call(s) reached the session", s.reached)
	}
	h.On() // already on: does nothing, does not deadlock

	h.Off()
	h.Off() // already off: does nothing
	if _, err := kv.Read(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Versions(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := kv.Delete(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := tr.TransitCreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.TransitEncrypt(ctx, key, secret.Value{}); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.TransitDecrypt(ctx, key, secret.Value{}); err != nil {
		t.Fatal(err)
	}
	if err := tr.TransitDestroyKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if s.reached != 7 {
		t.Fatalf("%d calls passed through after Off, want 7", s.reached)
	}
	// Stick does nothing to a Hold that is off.
	h.Stick(jobID)
	if on, stuck := h.Held(); on || stuck {
		t.Fatalf("Stick on an off Hold: on %v stuck %v", on, stuck)
	}
	if _, err := NewHold(nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a nil state directory was accepted")
	}
}
