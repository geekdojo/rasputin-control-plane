package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

type noNodes struct{}

func (noNodes) List(context.Context) ([]*proto.Node, error) { return nil, nil }

// TC-772-16: the composition root's wiring gives the scheduler an entry for
// the registered workflow's kind, a daily interval with a start-time run
// before it, and one read_manifest step bounded at 2 minutes, not retried.
func TestSecurityWatchWiring_EntryAndWorkflow(t *testing.T) {
	log, _ := logkittest.New()
	w, err := securityWatchWiring(releases.NewGithubPublicSource("http://127.0.0.1:0", nil), noNodes{}, releases.ChannelStable, log)
	if err != nil {
		t.Fatal(err)
	}
	if w.workflow.Kind != "updates.security_check" || w.entry.Kind != w.workflow.Kind {
		t.Errorf("entry kind %q, workflow kind %q; want both updates.security_check", w.entry.Kind, w.workflow.Kind)
	}
	if w.entry.Interval != 24*time.Hour {
		t.Errorf("interval = %s, want 24h", w.entry.Interval)
	}
	if w.entry.InitialDelay <= 0 || w.entry.InitialDelay >= w.entry.Interval {
		t.Errorf("initial delay = %s, want between 0 and the interval", w.entry.InitialDelay)
	}
	if len(w.workflow.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(w.workflow.Steps))
	}
	st := w.workflow.Steps[0]
	if st.Name != "read_manifest" || st.Timeout != 2*time.Minute || st.Retries != 0 || st.Do == nil {
		t.Errorf("step = %q timeout %s retries %d; want read_manifest, 2m, 0", st.Name, st.Timeout, st.Retries)
	}
	if w.alerts == nil {
		t.Error("no alerts source")
	}
}

// A channel the watch cannot follow fails the wiring, which main turns into
// a FATAL exit.
func TestSecurityWatchWiring_RefusesAnUnknownChannel(t *testing.T) {
	log, _ := logkittest.New()
	_, err := securityWatchWiring(releases.NewGithubPublicSource("http://127.0.0.1:0", nil), noNodes{}, "beta", log)
	if err == nil || !strings.Contains(err.Error(), "security watch") {
		t.Errorf("err = %v, want a security watch refusal", err)
	}
}
