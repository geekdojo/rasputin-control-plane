package tileschema

import (
	"strings"
	"testing"
)

// operatorTile is TC-780-01's tile: an available tile declaring one operator
// secret behind both capabilities, whose compose uses it in environment:.
func operatorTile() Tile {
	t := okTile()
	t.Requires = []string{CapabilityTileSecrets, CapabilityOperatorSecrets}
	t.OperatorSecrets = []OperatorSecret{{Name: "feed-key", Label: "Feed API key"}}
	t.ComposeYAML = "services:\n  app:\n    environment:\n      FEED_KEY: ${secret:feed-key}\n"
	return t
}

// TC-780-01: a valid declaration is accepted.
func TestValidateTileAcceptsAnOperatorSecretDeclaration(t *testing.T) {
	if err := ValidateTile(operatorTile()); err != nil {
		t.Fatalf("a valid operator-secret declaration was refused: %v", err)
	}
}

// TC-780-02 to TC-780-06: each refusal, by message.
func TestValidateTileRefusesABadOperatorSecretDeclaration(t *testing.T) {
	cases := []struct {
		tc, why string
		mut     func(*Tile)
		want    []string
	}{
		{"TC-780-02", "capability missing", func(x *Tile) { x.Requires = []string{CapabilityTileSecrets} },
			[]string{`"tile.operator-secrets"`, "requires", "derive a random value"}},
		{"TC-780-03", "upper case and underscore", func(x *Tile) { x.OperatorSecrets[0].Name = "Feed_Key" },
			[]string{`operatorSecrets[0]: name "Feed_Key"`, "DNS-1123 label"}},
		{"TC-780-03", "leading hyphen", func(x *Tile) { x.OperatorSecrets[0].Name = "-key" },
			[]string{`name "-key"`, "DNS-1123 label"}},
		{"TC-780-03", "64 characters", func(x *Tile) { x.OperatorSecrets[0].Name = strings.Repeat("a", 64) },
			[]string{"DNS-1123 label"}},
		{"TC-780-03", "empty name", func(x *Tile) { x.OperatorSecrets[0].Name = "" },
			[]string{`name ""`, "DNS-1123 label"}},
		{"TC-780-04", "duplicate", func(x *Tile) {
			x.OperatorSecrets = append(x.OperatorSecrets, OperatorSecret{Name: "feed-key", Label: "Again"})
		}, []string{`operatorSecrets[1] "feed-key"`, "duplicate name"}},
		{"TC-780-05", "empty label", func(x *Tile) { x.OperatorSecrets[0].Label = "" },
			[]string{`operatorSecrets[0] "feed-key"`, "label is required"}},
		{"TC-780-05", "blank label", func(x *Tile) { x.OperatorSecrets[0].Label = "   " },
			[]string{`operatorSecrets[0] "feed-key"`, "label is required"}},
		{"TC-780-06", "declared but unused", func(x *Tile) {
			x.ComposeYAML = "services:\n  app:\n    environment:\n      K: ${secret:other}\n"
		}, []string{`operatorSecrets[0] "feed-key"`, "never uses ${secret:feed-key}"}},
	}
	for _, c := range cases {
		t.Run(c.tc+" "+c.why, func(t *testing.T) {
			tile := operatorTile()
			c.mut(&tile)
			err := ValidateTile(tile)
			if err == nil {
				t.Fatalf("%s: accepted a tile with %s", c.tc, c.why)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%s: refusal %q does not contain %q", c.tc, err, w)
				}
			}
		})
	}
}

// TC-780-06, second half: a preview tile ships no compose, so it has no tokens
// to check its declarations against, and it is accepted.
func TestValidateTileAcceptsAPreviewTileDeclaringOperatorSecrets(t *testing.T) {
	tile := operatorTile()
	tile.Status = StatusPreview
	tile.ComposeYAML = ""
	if err := ValidateTile(tile); err != nil {
		t.Fatalf("a preview tile with no compose declaring operator secrets was refused: %v", err)
	}
}

// TC-780-07: a control plane that does not know tile.operator-secrets refuses
// the tile, available and preview alike, because the must-understand loop runs
// first. The bundle's one-bad-tile-costs-one-tile behaviour is proven by
// bundle_test.go and not re-proved here.
func TestOperatorSecretsTileIsRefusedByAReaderWithoutTheCapability(t *testing.T) {
	if !KnownCapabilities[CapabilityOperatorSecrets] {
		t.Fatalf("%q is not in KnownCapabilities", CapabilityOperatorSecrets)
	}
	if len(KnownCapabilities) != 4 {
		t.Fatalf("KnownCapabilities holds %d entries, want 4", len(KnownCapabilities))
	}

	delete(KnownCapabilities, CapabilityOperatorSecrets)
	t.Cleanup(func() { KnownCapabilities[CapabilityOperatorSecrets] = true })

	available := operatorTile()
	preview := operatorTile()
	preview.Status = StatusPreview
	preview.ComposeYAML = ""
	for name, tile := range map[string]Tile{"available": available, "preview": preview} {
		err := ValidateTile(tile)
		if err == nil {
			t.Fatalf("%s tile was accepted by a reader that does not know %q", name, CapabilityOperatorSecrets)
		}
		if !strings.Contains(err.Error(), "requires unknown capability") {
			t.Errorf("%s tile: refusal %q is not the must-understand refusal", name, err)
		}
	}
}

// TC-604-01: a declaration is required unless it says `required: false`; a
// tile carrying the field validates; the one name lookup finds a declared
// name and nothing else.
func TestOperatorSecretRequiredAndLookup(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		why  string
		req  *bool
		want bool
	}{
		{"absent", nil, true},
		{"true", &yes, true},
		{"false", &no, false},
	} {
		if got := (OperatorSecret{Name: "k", Label: "K", Required: c.req}).IsRequired(); got != c.want {
			t.Errorf("required %s: IsRequired() = %v, want %v", c.why, got, c.want)
		}
	}

	tile := operatorTile()
	tile.OperatorSecrets[0].Required = &no
	if err := ValidateTile(tile); err != nil {
		t.Fatalf("a tile declaring required:false was refused: %v", err)
	}

	decls := []OperatorSecret{{Name: "feed-key", Label: "Feed API key"}, {Name: "opt-key", Label: "Optional", Required: &no}}
	got, ok := OperatorSecretByName(decls, "opt-key")
	if !ok || got.Name != "opt-key" || got.Label != "Optional" || got.IsRequired() {
		t.Errorf("OperatorSecretByName(opt-key) = %+v, %v; want the optional declaration", got, ok)
	}
	got, ok = OperatorSecretByName(decls, "db-password")
	if ok || got != (OperatorSecret{}) {
		t.Errorf("OperatorSecretByName(db-password) = %+v, %v; want the zero declaration and false", got, ok)
	}
}
