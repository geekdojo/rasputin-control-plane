package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The mint endpoint returns the RENDERED seed (methodology §5.6, §7 4.2,
// geekdojo/geekdojo-brain#540).
//
// The UI used to assemble one from this response, with its own quoting rules
// and its own default cluster name. There is one renderer now, and this is the
// only place a UI-minted seed comes from — so what the endpoint returns is
// what a node is provisioned with, and it is asserted here rather than in a
// comment.

func mintSeed(t *testing.T, f *apiFixture, cookie *http.Cookie, body string) (seed string, raw map[string]string) {
	t.Helper()
	w := f.do(t, http.MethodPost, "/api/bus/tokens", body, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint = %d %s", w.Code, w.Body.String())
	}
	raw = map[string]string{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode mint: %v", err)
	}
	return raw["seed"], raw
}

func TestMintBusToken_ReturnsARenderedSeed(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	seed, raw := mintSeed(t, f, cookie, `{"role":"compute","label":"compute","nodeId":"home1-compute1","sshAuthorizedKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3Nzb1c me@laptop"}`)
	if seed == "" {
		t.Fatalf("no seed in the mint response: %v", raw)
	}
	got, err := proto.ParseSeed(strings.NewReader(seed))
	if err != nil {
		t.Fatalf("the seed does not parse: %v\n%s", err, seed)
	}
	if got.Role != proto.RoleCompute {
		t.Errorf("role = %q", got.Role)
	}
	if got.NodeID != "home1-compute1" {
		t.Errorf("node id = %q", got.NodeID)
	}
	// The fixture's cluster is test1 / test1.local, so the seed must name
	// THAT bus — not the rasputin.local default, which is the bug this
	// endpoint exists to make impossible (control-plane #70).
	if got.ClusterID != "test1" {
		t.Errorf("cluster id = %q, want the fixture's cluster", got.ClusterID)
	}
	if got.NATSURL != "nats://test1.local:4222" {
		t.Errorf("nats url = %q, want the cluster's own name", got.NATSURL)
	}
	// The token in the seed is the token the response returned: one mint,
	// one credential, and a seed that can never pair a token with another
	// moment's pin.
	if got.JoinToken != raw["token"] {
		t.Errorf("the seed's token is not the minted one")
	}
	if got.BusPin != raw["busPin"] {
		t.Errorf("the seed's pin = %q, the response's = %q", got.BusPin, raw["busPin"])
	}
	if got.SSHAuthorizedKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3Nzb1c me@laptop" {
		t.Errorf("ssh key = %q", got.SSHAuthorizedKey)
	}
	// A firewall seed is the same file under the firewall's own name.
	fwSeed, _ := mintSeed(t, f, cookie, `{"role":"firewall","label":"firewall","nodeId":"home1-fw"}`)
	fw, err := proto.ParseSeed(strings.NewReader(fwSeed))
	if err != nil {
		t.Fatal(err)
	}
	if fw.Role != proto.RoleFirewall || fw.NodeID != "home1-fw" {
		t.Errorf("firewall seed = %+v", fw)
	}
	if !strings.Contains(fwSeed, proto.SeedFileNameFirewall) {
		t.Errorf("the firewall seed's header does not name its file:\n%s", fwSeed)
	}
}

// An explicit empty key is a console/UI-only node, and a valid answer. An
// ABSENT field means "whatever is saved", which is the wizard's prefill.
func TestMintBusToken_SSHKeyIsExplicitOrTheSavedOne(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	seed, _ := mintSeed(t, f, cookie, `{"role":"compute","label":"compute","nodeId":"n-nokey","sshAuthorizedKey":""}`)
	if strings.Contains(seed, proto.SeedKeySSHKey) {
		t.Errorf("an explicit empty key still rendered a key line:\n%s", seed)
	}

	// Save an operator key, then mint without naming one.
	const saved = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3Nzb1c saved@laptop"
	if _, err := f.srv.setup.SetOperatorSSHKey(t.Context(), saved); err != nil {
		t.Fatal(err)
	}
	seed, _ = mintSeed(t, f, cookie, `{"role":"compute","label":"compute","nodeId":"n-saved"}`)
	got, err := proto.ParseSeed(strings.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHAuthorizedKey != saved {
		t.Errorf("ssh key = %q, want the saved operator key", got.SSHAuthorizedKey)
	}
}

// A key the wizard would refuse is refused here too, by the same rule, and
// nothing is minted — a cluster provisioned two ways from one keyboard is
// what one rule exists to prevent (geekdojo/geekdojo-brain#545).
func TestMintBusToken_RefusesAnInvalidSSHKey(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	for _, key := range []string{
		"not a key",
		"ssh-dss AAAAB3NzaC1kc3MAAACBAP me@laptop",
		// Spaced on purpose — see ui/lib/operator-ssh-key-vectors.json.
		"----- BEGIN OPENSSH PRIVATE KEY ----- b3BlbnNzaC1rZXktdjEAAAAA",
	} {
		body, err := json.Marshal(map[string]string{"role": "compute", "label": "compute", "nodeId": "n-bad", "sshAuthorizedKey": key})
		if err != nil {
			t.Fatal(err)
		}
		w := f.do(t, http.MethodPost, "/api/bus/tokens", string(body), cookie)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: mint = %d %s, want 400", key, w.Code, w.Body.String())
		}
	}
}
