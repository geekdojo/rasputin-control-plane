//go:build buscompat

package bustls_test

// THE COMPATIBILITY TESTS for the release that deletes the plaintext ladder
// (geekdojo/geekdojo-brain#517), against binaries built from the floor release,
// v2026.09.5. A node running that agent must keep working on the new api, and
// the new agent must work on that api, because an upgrade updates nodes and the
// controlplane at different moments (computes first, the controlplane after).
//
// They need the two old binaries, named by RASPUTIN_BUSCOMPAT_OLD_AGENT and
// RASPUTIN_BUSCOMPAT_OLD_API. Unset, the tests FAIL rather than skip: a run that
// silently tested nothing would read as a pass. The `backend` CI job and
// `scripts/test-bus-tls.sh --compat` build them from the tag and run these
// with -tags buscompat; both fail when the tag or a build is missing.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// oldBinary is the path in env, and fails the test when it names nothing.
func oldBinary(t *testing.T, env string) string {
	t.Helper()
	p := os.Getenv(env)
	if p == "" {
		t.Fatalf("%s is unset: the compatibility tests need the v2026.09.5 binaries (scripts/test-bus-tls.sh --compat builds them)", env)
	}
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		t.Fatalf("%s=%q is not a binary: %v", env, p, err)
	}
	return p
}

// TC-517-31: an agent of the floor release, holding the pin, joins the new
// api's TLS-only bus and registers; it still sends busTls, which nothing reads
// any more, and its node keys are recorded without it.
func TestCompat_FloorAgentOnTheNewAPI(t *testing.T) {
	old := oldBinary(t, "RASPUTIN_BUSCOMPAT_OLD_AGENT")
	c := startCP(t, cpOpts{})
	startAgent(t, agentOpts{bin: old, id: "n-floor", url: c.url(), token: c.mint(t, "n-floor"), pin: c.key.Pin()})
	ev := c.waitRegistered(t, "n-floor")
	if v, ok := ev.Metadata["busTls"]; !ok || v != true {
		t.Fatalf("the floor agent registered with busTls=%v (present %v); this test is only meaningful against an agent that sends it", v, ok)
	}
	c.waitRecorded(t, "n-floor")
	keys, err := c.inv.NodeKeys(context.Background(), "n-floor")
	if err != nil || len(keys) == 0 {
		t.Fatalf("the floor agent's node keys = (%v, %v), want them recorded", keys, err)
	}
}

// TC-517-32: the new agent on the floor release's api, which is at require.
// It joins and registers; that api still wants busTls before it takes node
// keys, so it logs that it refuses them and records none. Swapping the api for
// this release's build — same data dir, same ports — records them on the
// agent's next registration, with the agent process never restarted.
func TestCompat_NewAgentOnTheFloorAPI(t *testing.T) {
	oldAPI := oldBinary(t, "RASPUTIN_BUSCOMPAT_OLD_API")
	const node = "n-new"
	token := "compat-token-" + node
	opts := apiOpts{
		bin:    oldAPI,
		noSeed: true,
		preseed: []busauth.PreseedToken{{
			Hash: busauth.HashToken(token), NodeID: node, Label: node, Role: proto.RoleCompute,
		}},
	}
	api, _ := startAPI(t, opts)
	pinBytes, err := os.ReadFile(filepath.Join(api.dataDir, "bus", proto.BusAgentPinFileName))
	if err != nil {
		t.Fatalf("the floor api wrote no agent.pin: %v", err)
	}
	pin := strings.TrimSpace(string(pinBytes))

	a := startAgent(t, agentOpts{id: node, url: "nats://127.0.0.1:" + itoa(api.natsPort), token: token, pin: pin})
	a.waitLog(t, "the new agent on the floor api's bus", "agent/bus: connected")
	api.waitLog(t, "the floor api refusing the new agent's keys", "WARN refusing node keys from "+node)
	since := a.lineCount()
	api.stop()
	if keys := nodeKeysIn(t, api.dataDir, node); len(keys) != 0 {
		t.Fatalf("the floor api recorded keys %v it logged it refused", keys)
	}

	// The swap: this release's api on the same data dir and ports.
	opts.bin, opts.dataDir, opts.httpPort, opts.natsPort = "", api.dataDir, httpPortOf(api), api.natsPort
	opts.preseed = nil
	api2, _ := startAPI(t, opts)
	a.waitLogSince(t, since, "the same agent back on the new api", "agent/bus: reconnected")
	api2.waitLog(t, "the new api recording the keys", "inventory: "+node+" registered node key(s)")
	api2.stop()
	if keys := nodeKeysIn(t, api2.dataDir, node); len(keys) == 0 {
		t.Fatal("the new api did not record the agent's node keys")
	}
	if a.exited() {
		t.Fatal("the agent process ended")
	}
}

// nodeKeysIn reads id's recorded keys from a stopped api's database.
func nodeKeysIn(t *testing.T, dataDir, id string) proto.NodeKeys {
	t.Helper()
	inv, err := inventory.OpenStore(context.Background(), filepath.Join(dataDir, "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inv.Close() }()
	keys, err := inv.NodeKeys(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func itoa(n int) string { return strconv.Itoa(n) }

// httpPortOf is the HTTP port an apiProc listens on.
func httpPortOf(a *apiProc) int {
	_, port, _ := strings.Cut(strings.TrimPrefix(a.httpBase, "http://"), ":")
	n, _ := strconv.Atoi(port)
	return n
}
