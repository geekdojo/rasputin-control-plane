package obs

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Every shipped default must satisfy the same rule a tile from a signed
// catalog satisfies. A default that regressed to a bare tag would otherwise
// only be caught by whoever next read the file.
func TestShippedDefaultsAreDigestPinned(t *testing.T) {
	for name, ref := range map[string]string{
		"defaultVMImage":      defaultVMImage,
		"defaultAlloyImage":   defaultAlloyImage,
		"defaultLokiImage":    defaultLokiImage,
		"defaultGrafanaImage": defaultGrafanaImage,
		"defaultVMAlertImage": defaultVMAlertImage,
	} {
		if err := tileschema.ValidateImagePin(ref); err != nil {
			t.Errorf("%s = %q: %v", name, ref, err)
		}
		// The tag is kept alongside the digest deliberately: an operator
		// reading `docker ps` should not have to resolve a digest to learn
		// which version is running.
		if !strings.Contains(ref[:strings.Index(ref, "@")], ":") {
			t.Errorf("%s = %q: the digest is there but the version tag was dropped", name, ref)
		}
	}
}

// The override is the half that had no validator at all, so it is the half
// worth testing: an operator pointing the stack at a local build must be
// refused at construction, not at `compose up`.
func TestUnpinnedOverrideRefusesConstruction(t *testing.T) {
	f := false
	for _, tc := range []struct {
		name   string
		mutate func(*DockerComposeSupervisorConfig)
		wantIn string
	}{
		{"vm", func(c *DockerComposeSupervisorConfig) { c.VMImage = "victoriametrics/victoria-metrics:latest" }, "RASPUTIN_OBS_VM_IMAGE"},
		{"alloy", func(c *DockerComposeSupervisorConfig) { c.AlloyImage = "grafana/alloy:v1.4.2" }, "RASPUTIN_OBS_ALLOY_IMAGE"},
		{"loki", func(c *DockerComposeSupervisorConfig) { c.LokiImage = "grafana/loki:3.4.1" }, "RASPUTIN_OBS_LOKI_IMAGE"},
		{"grafana", func(c *DockerComposeSupervisorConfig) { c.GrafanaImage = "grafana/grafana:11.5.1" }, "RASPUTIN_OBS_GRAFANA_IMAGE"},
		{"vmalert", func(c *DockerComposeSupervisorConfig) { c.VMAlertImage = "victoriametrics/vmalert:v1.103.0" }, "RASPUTIN_OBS_VMALERT_IMAGE"},
		{"digest is not sha256", func(c *DockerComposeSupervisorConfig) {
			c.VMImage = "victoriametrics/victoria-metrics:v1@sha1:abc"
		}, "digest must be sha256"},
		{"digest is the wrong length", func(c *DockerComposeSupervisorConfig) {
			c.VMImage = "victoriametrics/victoria-metrics:v1@sha256:abcd"
		}, "64 hex chars"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DockerComposeSupervisorConfig{
				StateDir:      t.TempDir(),
				EnableLoki:    &f,
				EnableGrafana: &f,
			}
			tc.mutate(&cfg)
			_, err := NewDockerComposeSupervisor(cfg)
			if err == nil {
				t.Fatal("an unpinned image reference was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
		})
	}
}

// Several bad overrides are reported together. An operator pointing a dev
// stack at local builds sets more than one at a time, and a one-at-a-time gate
// turns that into as many restarts as they set.
func TestUnpinnedOverridesAreAllReported(t *testing.T) {
	f := false
	_, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      t.TempDir(),
		VMImage:       "victoriametrics/victoria-metrics:latest",
		LokiImage:     "grafana/loki:latest",
		EnableLoki:    &f,
		EnableGrafana: &f,
	})
	if err == nil {
		t.Fatal("unpinned references were accepted")
	}
	for _, want := range []string{"RASPUTIN_OBS_VM_IMAGE", "RASPUTIN_OBS_LOKI_IMAGE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q too", err, want)
		}
	}
}

// inspectFake is a fakeCompose that can also fail `docker image inspect` for
// named images, which is how "the image is not in the local store" is
// expressed to the supervisor.
type inspectFake struct {
	mu       sync.Mutex
	inner    *fakeCompose
	missing  map[string]bool
	daemonUp bool
	inspects []string
}

func newInspectFake(missing ...string) *inspectFake {
	m := map[string]bool{}
	for _, s := range missing {
		m[s] = true
	}
	return &inspectFake{inner: newFakeCompose(), missing: m, daemonUp: true}
}

func (i *inspectFake) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
		ref := args[len(args)-1]
		i.mu.Lock()
		i.inspects = append(i.inspects, ref)
		miss := i.missing[ref]
		i.mu.Unlock()
		if miss {
			return []byte("Error: No such image"), errors.New("exit status 1")
		}
		return []byte("sha256:deadbeef\n"), nil
	}
	if len(args) >= 1 && args[0] == "version" {
		i.mu.Lock()
		up := i.daemonUp
		i.mu.Unlock()
		if !up {
			return nil, errors.New("cannot connect to the Docker daemon")
		}
		return []byte("29.1.3\n"), nil
	}
	return i.inner.run(ctx, name, args...)
}

func newPullFailSupervisor(t *testing.T, runner CmdRunner) *DockerComposeSupervisor {
	t.Helper()
	vm := newStubVM()
	srv := httptest.NewServer(vm.handler())
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	f := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:      t.TempDir(),
		VMListenAddr:  host + ":" + port,
		Runner:        runner,
		HTTPClient:    srv.Client(),
		HealthTimeout: 2 * time.Second,
		PullTimeout:   time.Second,
		EnableLoki:    &f,
		EnableGrafana: &f,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return sup
}

// The behaviour this replaces: a failed pull was logged and Start carried on,
// so "the registry was unreachable" and "this image is not here and never was"
// had the same outcome — and a `compose up` that then found a STALE image of
// the right name started it without comment.
func TestStart_PullFailureWithAMissingImageFailsClosed(t *testing.T) {
	fake := newInspectFake(defaultVMImage)
	fake.inner.errOnSub["pull"] = errors.New("registry unreachable")
	sup := newPullFailSupervisor(t, fake.run)

	err := sup.Start(context.Background())
	if err == nil {
		t.Fatal("Start continued after a failed pull with an image that is not present")
	}
	// The pull error names the real cause and must survive into the message.
	if !strings.Contains(err.Error(), "registry unreachable") {
		t.Errorf("error = %v, want it to carry the pull failure", err)
	}
	if !strings.Contains(err.Error(), defaultVMImage) {
		t.Errorf("error = %v, want it to name the missing image", err)
	}
	for _, sub := range fake.inner.subcommands() {
		if sub == "up" {
			t.Error("`compose up` ran after a pull failure with a missing image")
		}
	}
}

// "Every image is missing" is what a dead daemon looks like from here, and it
// is a different problem with a different fix. Say which one it is.
func TestStart_PullFailureWithADeadDaemonSaysSo(t *testing.T) {
	// Every image this stack would run: "all of them are missing" is what a
	// dead daemon looks like from here, and is the case the check exists for.
	fake := newInspectFake(defaultVMImage, defaultAlloyImage, defaultVMAlertImage)
	fake.daemonUp = false
	fake.inner.errOnSub["pull"] = errors.New("registry unreachable")
	sup := newPullFailSupervisor(t, fake.run)

	err := sup.Start(context.Background())
	if err == nil {
		t.Fatal("Start continued with no daemon")
	}
	if !strings.Contains(err.Error(), "daemon is not answering") {
		t.Errorf("error = %v, want it to distinguish a dead daemon from missing images", err)
	}
}

// Only the images this stack will actually run are required. A disabled
// service's image being absent must not block an offline start.
func TestStart_PullFailureIgnoresDisabledServices(t *testing.T) {
	fake := newInspectFake(defaultLokiImage, defaultGrafanaImage)
	fake.inner.errOnSub["pull"] = errors.New("registry unreachable")
	sup := newPullFailSupervisor(t, fake.run)

	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start refused over images belonging to disabled services: %v", err)
	}
	for _, ref := range fake.inspects {
		if ref == defaultLokiImage || ref == defaultGrafanaImage {
			t.Errorf("a disabled service's image (%s) was required to be present", ref)
		}
	}
}

// The per-node collector compose is the last place a reference is seen before
// it leaves this box and becomes a `docker compose up` on an agent.
func TestBuildCollectorCompose_RefusesAnUnpinnedImage(t *testing.T) {
	_, err := BuildCollectorCompose(CollectorSpec{
		NodeID:         "node-1",
		IngressBaseURL: "https://rasputin.local",
		ServerName:     "rasputin.local",
		LeafCertPEM:    "x",
		LeafKeyPEM:     "x",
		MeshCAPEM:      "x",
		AlloyImage:     "grafana/alloy:v1.4.2",
	})
	if err == nil {
		t.Fatal("an unpinned collector image was rendered into a compose file for an agent to run")
	}
	if !strings.Contains(err.Error(), "digest-pinned") {
		t.Errorf("error = %v, want it to say why", err)
	}
}
