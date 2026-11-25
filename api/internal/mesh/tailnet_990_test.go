package mesh

import (
	"bytes"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

// TC-990-17: the Headscale config's prefixes render from TailnetPrefixes,
// byte-identical to the literal render before geekdojo/geekdojo-brain#990
// (testdata/headscale-config.golden), and the prefixes it names are
// TailnetPrefixes.
func TestRenderConfig_TC990_17_PrefixesFromTailnetPrefixes(t *testing.T) {
	s, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir(), ClusterID: "home1", ServerURL: "http://192.0.2.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s.renderConfig()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/headscale-config.golden")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Errorf("the rendered config differs from the literal render:\n%s", body)
	}
	var rendered []netip.Prefix
	for _, line := range strings.Split(string(body), "\n") {
		for _, k := range []string{"  v4: ", "  v6: "} {
			if v, ok := strings.CutPrefix(line, k); ok {
				p, err := netip.ParsePrefix(v)
				if err != nil {
					t.Fatalf("prefix line %q: %v", line, err)
				}
				rendered = append(rendered, p)
			}
		}
	}
	if !slices.Equal(rendered, TailnetPrefixes()) {
		t.Errorf("rendered prefixes %v, want TailnetPrefixes %v", rendered, TailnetPrefixes())
	}
	a := TailnetPrefixes()
	a[0] = netip.Prefix{}
	if !TailnetPrefixes()[0].IsValid() {
		t.Error("TailnetPrefixes shares its slice with callers")
	}
}
