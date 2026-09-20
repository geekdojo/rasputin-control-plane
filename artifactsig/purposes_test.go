package artifactsig

import (
	"encoding/asn1"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Validator parity for artifact classes (geekdojo/geekdojo-brain#495, gate 8).
//
// TestVerifyForPurpose_CrossPurposeMatrix proves the two purposes that exist
// today cannot sign for each other. What it cannot prove is that they are the
// only two: a third purpose added tomorrow would sit outside the matrix, its
// leaf would never be tried against another class's artifact, and the split
// that is the whole point of the OIDs would be untested for it.
//
// So this reads the purposes actually DECLARED in eku.go and holds the matrix
// to them. Adding a purpose fails this test until it has been added to the
// registry below, and adding it there fails the matrix until a fixture signed
// under it exists — which is the order those two things have to happen in.

// purposeRegistry is every artifact class and the purpose OID it is signed
// under. It is checked against eku.go's declarations, so it cannot fall
// behind them.
var purposeRegistry = []struct {
	Name    string
	OID     asn1.ObjectIdentifier
	Classes []string
	// Fixture is the signature in testdata signed under this purpose, and the
	// thing a new class owes before it can be listed.
	Fixture string
}{
	{
		Name: "OIDCodeSigningRelease",
		OID:  OIDCodeSigningRelease,
		Classes: []string{
			"the firewall rootfs the agent flashes",
			"the OS release manifest",
			"an uploaded bundle",
		},
		Fixture: "payload.bin.sig",
	},
	{
		Name:    "OIDCodeSigningCatalog",
		OID:     OIDCodeSigningCatalog,
		Classes: []string{"a catalog bundle", "the embedded catalog floor"},
		Fixture: "payload.bin.catalog.sig",
	},
}

var purposeDecl = regexp.MustCompile(`^OIDCodeSigning\w+$`)

// TestPurposeRegistryMatchesTheDeclaredOIDs is the completeness half.
func TestPurposeRegistryMatchesTheDeclaredOIDs(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "eku.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse eku.go: %v", err)
	}

	var declared []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range vs.Names {
			if purposeDecl.MatchString(name.Name) {
				declared = append(declared, name.Name)
			}
		}
		return true
	})
	if len(declared) == 0 {
		t.Fatal("no purpose OIDs found in eku.go — the scan is broken, and a broken " +
			"scan makes this whole check pass over every purpose there is")
	}

	registered := map[string]bool{}
	for _, p := range purposeRegistry {
		if registered[p.Name] {
			t.Errorf("%s is registered twice", p.Name)
		}
		registered[p.Name] = true
		if len(p.Classes) == 0 {
			t.Errorf("%s names no artifact class; a purpose nothing is signed under "+
				"is a purpose nobody can reason about", p.Name)
		}
		if p.Fixture == "" {
			t.Errorf("%s names no fixture, so the matrix below cannot exercise it", p.Name)
		}
	}

	sort.Strings(declared)
	for _, name := range declared {
		if !registered[name] {
			t.Errorf("eku.go declares %s, which is not in purposeRegistry. Every artifact "+
				"class goes through the cross-purpose matrix, or the split the OIDs exist "+
				"for is untested for that class. Add it here, and add a fixture signed "+
				"under it to testdata.", name)
		}
	}
	for _, p := range purposeRegistry {
		found := false
		for _, name := range declared {
			if name == p.Name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("purposeRegistry names %s, which eku.go no longer declares", p.Name)
		}
	}

	t.Logf("artifact purposes: %d declared · %d registered · %d classes",
		len(declared), len(purposeRegistry), countClasses())
}

func countClasses() int {
	n := 0
	for _, p := range purposeRegistry {
		n += len(p.Classes)
	}
	return n
}

// TestEveryRegisteredPurposeIsCrossChecked runs the matrix over the registry
// rather than over two hand-written pairs, so a purpose added to the registry
// is exercised against every other one without anyone extending a test.
func TestEveryRegisteredPurposeIsCrossChecked(t *testing.T) {
	if len(purposeRegistry) < 2 {
		t.Skip("a cross-purpose matrix needs at least two purposes")
	}
	root := fixture(t, "root-ca.pem")

	for _, signed := range purposeRegistry {
		for _, want := range purposeRegistry {
			name := signed.Name + " verified for " + want.Name
			t.Run(name, func(t *testing.T) {
				_, err := VerifyForPurpose(
					fixture(t, "payload.bin"),
					fixture(t, signed.Fixture),
					root,
					want.OID,
				)
				if signed.Name == want.Name {
					if err != nil {
						t.Fatalf("a leaf signed under %s could not verify its own artifact "+
							"class (%s): %v", signed.Name, strings.Join(signed.Classes, ", "), err)
					}
					return
				}
				if err == nil {
					t.Fatalf("a leaf signed under %s verified an artifact of a class that "+
						"belongs to %s (%s). The split between these purposes is the only "+
						"thing keeping one signing credential out of the other's artifacts.",
						signed.Name, want.Name, strings.Join(want.Classes, ", "))
				}
			})
		}
	}
}
