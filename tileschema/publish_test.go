package tileschema

import (
	"strings"
	"testing"
)

func webTile(port int) Tile {
	t := okTile()
	t.Ports = []Port{{Name: "web", Container: port, Published: port, Web: true}}
	return t
}

func factsWith(bindings ...PortBinding) SafetyFacts {
	f := okFacts()
	f.PortBindings = bindings
	return f
}

// TC-551-01: a web port published on loopback passes.
func TestValidateWebPortBind_LoopbackPasses(t *testing.T) {
	err := ValidateWebPortBind(webTile(8096), factsWith(PortBinding{HostIP: "127.0.0.1", Published: 8096}))
	if err != nil {
		t.Fatalf("a loopback web port must pass, got %v", err)
	}
}

// TC-551-02: a web port published anywhere but loopback is refused, and the
// refusal names the port, the host address and what to write instead.
func TestValidateWebPortBind_OffLoopbackRefused(t *testing.T) {
	cases := map[string]string{
		"":             "every interface",
		"0.0.0.0":      "0.0.0.0",
		"::":           "::",
		"192.168.1.10": "192.168.1.10",
	}
	for hostIP, named := range cases {
		t.Run(named, func(t *testing.T) {
			err := ValidateWebPortBind(webTile(8096), factsWith(PortBinding{HostIP: hostIP, Published: 8096}))
			if err == nil {
				t.Fatalf("web port on %q must be refused", hostIP)
			}
			for _, want := range []string{"8096", named, "127.0.0.1:"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not contain %q", err, want)
				}
			}
		})
	}
}

// TC-551-03: loopback plus every interface for the same port is refused.
func TestValidateWebPortBind_MixedPairRefused(t *testing.T) {
	err := ValidateWebPortBind(webTile(8096), factsWith(
		PortBinding{HostIP: "127.0.0.1", Published: 8096},
		PortBinding{HostIP: "", Published: 8096},
	))
	if err == nil {
		t.Fatal("a second all-interface publish of the web port must be refused")
	}
	for _, want := range []string{"8096", "every interface"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
}

// TC-551-04: ports other than the web port are not checked (the arr-stack shape).
func TestValidateWebPortBind_ClientConnectPortsUnchanged(t *testing.T) {
	err := ValidateWebPortBind(webTile(8989), factsWith(
		PortBinding{HostIP: "", Published: 7878},
		PortBinding{HostIP: "127.0.0.1", Published: 8989},
		PortBinding{HostIP: "", Published: 8090},
		PortBinding{HostIP: "", Published: 9696},
	))
	if err != nil {
		t.Fatalf("non-web ports on every interface must pass, got %v", err)
	}
}

// TC-551-05: a tile with no web port passes (the minecraft shape).
func TestValidateWebPortBind_NoWebPortPasses(t *testing.T) {
	tile := okTile()
	tile.Ports = []Port{{Name: "game", Container: 25565, Published: 25565}}
	if err := ValidateWebPortBind(tile, factsWith(PortBinding{Published: 25565})); err != nil {
		t.Fatalf("a page-less tile must pass, got %v", err)
	}
}

// TC-551-06: host networking with no binding passes; host networking plus an
// all-interface publish of the web port is still refused.
func TestValidateWebPortBind_HostNetwork(t *testing.T) {
	f := factsWith()
	f.HostNetwork = true
	if err := ValidateWebPortBind(webTile(8123), f); err != nil {
		t.Fatalf("host networking with no binding must pass, got %v", err)
	}
	f = factsWith(PortBinding{HostIP: "", Published: 8123})
	f.HostNetwork = true
	err := ValidateWebPortBind(webTile(8123), f)
	if err == nil {
		t.Fatal("a bridge publish of the web port off loopback must be refused even with host networking")
	}
	if !strings.Contains(err.Error(), "8123") {
		t.Errorf("refusal %q does not name 8123", err)
	}
}

// TC-551-07: an unpublished web port fails closed, and says so rather than
// claiming it is off loopback (F-551-03).
func TestValidateWebPortBind_UnpublishedRefused(t *testing.T) {
	for name, f := range map[string]SafetyFacts{
		"other ports only": factsWith(PortBinding{HostIP: "", Published: 9000}),
		"no bindings":      factsWith(),
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateWebPortBind(webTile(8096), f)
			if err == nil {
				t.Fatal("an unpublished web port must be refused")
			}
			if !strings.Contains(err.Error(), "web port 8096 is not published") {
				t.Errorf("refusal %q does not say web port 8096 is not published", err)
			}
			if strings.Contains(err.Error(), "loopback") {
				t.Errorf("refusal %q must not claim the port is off loopback", err)
			}
		})
	}
}
