package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

// The leaves a configuration must renew, and the refusal when one of them is on
// nothing.
//
// Why this test exists. The single renewal driver (§7.1, #518) is only as good
// as the set registered with it, and every Register call sits inline in main()
// beside whatever dependency it needs — api-https next to the TLS listener,
// headscale next to the mesh wiring, the collectors next to the job runner.
// Delete any one of them and nothing objects: it compiles, the whole suite
// passes, and that certificate silently stops being renewed until it expires
// months later in service. That is the exact failure the one-driver design was
// built to prevent, reintroduced one line at a time.
//
// main() has no seam a test can call, so the check is a fact evaluated at
// startup rather than a test of main itself: what IS registered, against what
// this configuration says it holds. Both halves are pure and are tested here.

func TestRequiredLeafConsumers_FollowsTheConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		httpsEnabled, selfHostedMesh bool
		want                         []string
	}{
		{"appliance: https and self-hosted headscale", true, true, []string{"api-https", mesh.HeadscaleLeafName}},
		// RASPUTIN_HTTPS_ADDR unset: plain HTTP, no leaf minted, none owed.
		{"dev: no https", false, true, []string{mesh.HeadscaleLeafName}},
		// A mock or external Headscale brings its own certificate — not ours.
		{"external or mock headscale", true, false, []string{"api-https"}},
		{"neither", false, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := requiredLeafConsumers(tc.httpsEnabled, tc.selfHostedMesh)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("requiredLeafConsumers(%v, %v) = %v, want %v",
					tc.httpsEnabled, tc.selfHostedMesh, got, tc.want)
			}
		})
	}
}

func TestVerifyLeafConsumers_RefusesALeafNothingWillRenew(t *testing.T) {
	required := requiredLeafConsumers(true, true)

	if err := verifyLeafConsumers([]string{"api-https", mesh.HeadscaleLeafName}, required); err != nil {
		t.Fatalf("a fully wired appliance must start: %v", err)
	}

	// An extra registration is fine — it is renewed, just not demanded here.
	if err := verifyLeafConsumers([]string{"api-https", mesh.HeadscaleLeafName, "something-else"}, required); err != nil {
		t.Errorf("an unlisted consumer is still renewed correctly: %v", err)
	}

	// Each half missing, which is what deleting one Register call looks like.
	for _, tc := range []struct {
		name       string
		registered []string
		wantNamed  string
	}{
		{"headscale's Register deleted", []string{"api-https"}, mesh.HeadscaleLeafName},
		{"the api's own Register deleted", []string{mesh.HeadscaleLeafName}, "api-https"},
		{"both deleted", nil, "api-https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyLeafConsumers(tc.registered, required)
			if err == nil {
				t.Fatalf("a leaf on no renewal driver must stop the api starting; "+
					"registered=%v required=%v", tc.registered, required)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("the error must NAME the leaf that would lapse; got %q, want it to mention %q",
					err, tc.wantNamed)
			}
		})
	}
}

// The other half of the check: RegisteredNames must actually report what main
// registered, or the check above passes on a lie.
func TestLeafSweeperRegisteredNames_ReportsWhatWasRegistered(t *testing.T) {
	dir := t.TempDir()
	ca, err := mesh.EnsureMeshCA(dir, "home1")
	if err != nil {
		t.Fatalf("mesh CA: %v", err)
	}
	s := mesh.NewLeafSweeper(ca)

	if got := s.RegisteredNames(); len(got) != 0 {
		t.Errorf("a fresh sweeper renews nothing, got %v", got)
	}

	spec := func() (mesh.LeafSpec, error) { return mesh.LeafSpec{CommonName: "x"}, nil }
	for _, name := range []string{mesh.HeadscaleLeafName, "api-https"} {
		if err := s.Register(mesh.LeafConsumer{Name: name, Dir: filepath.Join(dir, name), Spec: spec}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}

	// Sorted, so the check and its error message read the same way every run.
	if got := strings.Join(s.RegisteredNames(), ","); got != "api-https,headscale" {
		t.Errorf("RegisteredNames() = %q, want %q", got, "api-https,headscale")
	}

	// And the wiring check is satisfied by exactly this.
	if err := verifyLeafConsumers(s.RegisteredNames(), requiredLeafConsumers(true, true)); err != nil {
		t.Errorf("a sweeper holding both required leaves must verify: %v", err)
	}
}
