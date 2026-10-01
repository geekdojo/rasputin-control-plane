package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit"
)

// F-623-08: when admission cannot start, main logs FATAL with the error and
// exits 1: no node can join, so the api fails closed.
func TestAdmitAgents_FailureIsFatal(t *testing.T) {
	h := &recordsHandler{}
	var codes []int
	startErr := errors.New("bus admission: nats: connection closed")

	stop := admitAgents(context.Background(), slog.New(h), func(code int) { codes = append(codes, code) },
		func() (func(), error) { return nil, startErr })

	if len(codes) != 1 || codes[0] != 1 {
		t.Fatalf("exit calls %v, want exactly one exit(1)", codes)
	}
	fatal := h.matching(logkit.LevelFatal, "bus admission did not start")
	if len(fatal) != 1 {
		t.Fatalf("%d FATAL admission records, want 1", len(fatal))
	}
	var gotErr string
	fatal[0].Attrs(func(a slog.Attr) bool {
		if a.Key == "err" {
			gotErr = a.Value.String()
		}
		return true
	})
	if gotErr != startErr.Error() {
		t.Fatalf("FATAL record err=%q, want %q", gotErr, startErr.Error())
	}
	stop() // safe to defer even though exit returned
}

// F-623-08: when admission starts, main neither logs FATAL nor exits, and
// defers admission's own stop.
func TestAdmitAgents_SuccessReturnsStop(t *testing.T) {
	h := &recordsHandler{}
	exited := false
	stopped := 0

	stop := admitAgents(context.Background(), slog.New(h), func(int) { exited = true },
		func() (func(), error) { return func() { stopped++ }, nil })

	if exited {
		t.Fatal("admitAgents exited although admission started")
	}
	if n := len(h.matching(logkit.LevelFatal, "")); n != 0 {
		t.Fatalf("%d FATAL records although admission started, want 0", n)
	}
	stop()
	if stopped != 1 {
		t.Fatalf("the returned stop ran admission's stop %d time(s), want 1", stopped)
	}
}
