package obs

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// newTestStatus builds a Status over a fake supervisor + a real VMSink
// resolved against it. Snapshot needs both to be non-nil before it looks at
// anything else, so tests can't shortcut with a bare &Status{}.
func newTestStatus(t *testing.T, sup Supervisor) *Status {
	t.Helper()
	sink, err := NewVMSink(VMSinkConfig{Supervisor: sup})
	if err != nil {
		t.Fatalf("NewVMSink: %v", err)
	}
	return NewStatus(sup, sink, nil)
}

func enabledFn(on bool, err error) EnabledFn {
	return func(context.Context) (bool, error) { return on, err }
}

func TestSnapshot_StoredOptOutWins(t *testing.T) {
	// A healthy, fully-wired stack the operator has turned off must still
	// report off. Enablement is the stored choice, not "is a supervisor
	// wired" — that inference broke the moment the supervisor became
	// unconditional.
	st := newTestStatus(t, &fakeSupervisor{healthy: true, baseURL: "http://vm"})
	st.SetEnabled(enabledFn(false, nil))

	got := st.Snapshot(context.Background())
	if got.Enabled {
		t.Error("Enabled = true; want false when the operator has opted out")
	}
	if got.State != StateOff {
		t.Errorf("State = %q; want %q", got.State, StateOff)
	}
	if got.VMBaseURL != "" {
		t.Errorf("VMBaseURL = %q; want empty when off", got.VMBaseURL)
	}
}

func TestSnapshot_StartingIsNotOff(t *testing.T) {
	// The regression this guards: `enabled && healthy` collapsed into one
	// bool renders "observability is off" for the several minutes a cold
	// enable spends pulling ~500 MB — i.e. exactly while the operator is
	// watching the thing they just switched on.
	st := newTestStatus(t, &fakeSupervisor{healthy: false, baseURL: "http://vm"})
	st.SetEnabled(enabledFn(true, nil))

	got := st.Snapshot(context.Background())
	if !got.Enabled {
		t.Error("Enabled = false; want true — the operator did opt in")
	}
	if got.Healthy {
		t.Error("Healthy = true; want false")
	}
	if got.State != StateStarting {
		t.Errorf("State = %q; want %q — a starting stack must be distinguishable from a disabled one", got.State, StateStarting)
	}
}

func TestSnapshot_OnWhenHealthy(t *testing.T) {
	st := newTestStatus(t, &fakeSupervisor{healthy: true, baseURL: "http://vm", lokiURL: "http://loki"})
	st.SetEnabled(enabledFn(true, nil))

	got := st.Snapshot(context.Background())
	if got.State != StateOn {
		t.Errorf("State = %q; want %q", got.State, StateOn)
	}
	if got.VMBaseURL != "http://vm" || got.LokiBaseURL != "http://loki" {
		t.Errorf("URLs not surfaced when on: %+v", got)
	}
}

func TestSnapshot_SettingsReadErrorSurfaces(t *testing.T) {
	// A failed settings read must not masquerade as a deliberate opt-out —
	// that sends the operator hunting a toggle instead of a broken DB.
	st := newTestStatus(t, &fakeSupervisor{healthy: true, baseURL: "http://vm"})
	st.SetEnabled(enabledFn(false, errors.New("db is on fire")))

	got := st.Snapshot(context.Background())
	if got.State != StateOff {
		t.Errorf("State = %q; want %q", got.State, StateOff)
	}
	if !strings.Contains(got.LastError, "db is on fire") {
		t.Errorf("LastError = %q; want it to carry the underlying read failure", got.LastError)
	}
}

func TestSnapshot_NilEnabledFnFallsBackToStructural(t *testing.T) {
	// Back-compat: the obs package's own tests build a Status without a
	// settings store. A nil EnabledFn means "a wired supervisor is on".
	st := newTestStatus(t, &fakeSupervisor{healthy: true, baseURL: "http://vm"})

	got := st.Snapshot(context.Background())
	if !got.Enabled || got.State != StateOn {
		t.Errorf("got %+v; want enabled/on when no EnabledFn is installed", got)
	}
}

func TestSnapshot_NoopSupervisorIsOff(t *testing.T) {
	st := newTestStatus(t, NoopSupervisor{})
	st.SetEnabled(enabledFn(true, nil))

	got := st.Snapshot(context.Background())
	if got.Enabled || got.State != StateOff {
		t.Errorf("got %+v; want off — a noop supervisor has no real stack behind it", got)
	}
}

func TestGrafanaEnabled_RespectsStoredOptOut(t *testing.T) {
	// The /observability/* proxy gates on this. Without the opt-in check it
	// would forward to a container the operator just stopped and surface a
	// raw 502 instead of a clear "it's off".
	sup := &fakeSupervisor{healthy: true, baseURL: "http://vm", grafanaURL: "http://grafana"}
	st := newTestStatus(t, sup)

	st.SetEnabled(enabledFn(true, nil))
	if !st.GrafanaEnabled(context.Background()) {
		t.Fatal("GrafanaEnabled = false; want true when on and Grafana is configured")
	}
	if got := st.GrafanaBaseURL(context.Background()); got != "http://grafana" {
		t.Errorf("GrafanaBaseURL = %q; want the upstream", got)
	}

	st.SetEnabled(enabledFn(false, nil))
	if st.GrafanaEnabled(context.Background()) {
		t.Error("GrafanaEnabled = true; want false once the operator opts out")
	}
	if got := st.GrafanaBaseURL(context.Background()); got != "" {
		t.Errorf("GrafanaBaseURL = %q; want empty when off", got)
	}
}
