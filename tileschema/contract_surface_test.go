package tileschema

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The contract surface is every JSON wire field of the bundle with its Go type,
// plus every capability with the minor that introduced it. It is committed as
// a golden file; scripts/tileschema-contract.sh check compares the golden at
// the latest tileschema tag with this tree's, and refuses a change that did not
// bump ContractMinor (ADR-0012 Decision 3, geekdojo/geekdojo-brain#897).

var updateSurface = flag.Bool("update", false, "rewrite testdata/contract-surface.txt from the current types")

const surfaceGolden = "testdata/contract-surface.txt"

// contractSurface is the sorted surface of the real Bundle type and the real
// capability history.
func contractSurface() []string {
	lines := wireSurface(reflect.TypeOf(Bundle{}))
	for name, minor := range capabilityIntroducedIn {
		lines = append(lines, fmt.Sprintf("capability %s %d.%d", name, ContractMajor, minor))
	}
	slices.Sort(lines)
	return lines
}

// wireSurface lists one "<path> <go type>" line per JSON field reachable from
// t, following structs, slices, arrays, maps and pointers. It mirrors
// encoding/json's view: unexported fields and json:"-" fields are not on the
// wire, and an untagged embedded struct's fields are promoted.
func wireSurface(t reflect.Type) []string {
	var lines []string
	walkWire(t, "", map[reflect.Type]bool{}, &lines)
	slices.Sort(lines)
	return lines
}

func walkWire(t reflect.Type, path string, visiting map[reflect.Type]bool, lines *[]string) {
	switch t.Kind() {
	case reflect.Pointer:
		walkWire(t.Elem(), path, visiting, lines)
	case reflect.Slice, reflect.Array:
		walkWire(t.Elem(), path+"[]", visiting, lines)
	case reflect.Map:
		walkWire(t.Elem(), path+"{}", visiting, lines)
	case reflect.Struct:
		if visiting[t] {
			return // a recursive type: its fields are already listed above
		}
		visiting[t] = true
		defer delete(visiting, t)
		for i := range t.NumField() {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if tag == "-" {
				continue
			}
			if f.Anonymous && name == "" {
				walkWire(f.Type, path, visiting, lines)
				continue
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fieldPath := name
			if path != "" {
				fieldPath = path + "." + name
			}
			*lines = append(*lines, fieldPath+" "+f.Type.String())
			walkWire(f.Type, fieldPath, visiting, lines)
		}
	}
}

// TC-897-07: the real surface equals the committed golden, byte for byte.
func TestContractSurface(t *testing.T) {
	got := strings.Join(contractSurface(), "\n") + "\n"
	if *updateSurface {
		if err := os.MkdirAll(filepath.Dir(surfaceGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(surfaceGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(surfaceGolden)
	if err != nil {
		t.Fatalf("read the golden: %v", err)
	}
	if got != string(want) {
		t.Fatalf("the contract surface changed. Bump ContractMinor in tileschema/contract.go, then rerun "+
			"`go test ./tileschema -run TestContractSurface -update` and commit the golden.\n--- got\n%s--- want\n%s", got, want)
	}
}

type surfaceLeaf struct {
	Flag bool `json:"flag"`
}

type surfaceLeafPtr struct {
	Flag *bool `json:"flag"`
}

type surfaceFixture struct {
	List    []surfaceLeaf          `json:"list"`
	ByName  map[string]surfaceLeaf `json:"byName"`
	Maybe   *surfaceLeaf           `json:"maybe,omitempty"`
	Hidden  string                 `json:"-"`
	private string
	Untag   int
}

type surfaceFixtureChanged struct {
	List    []surfaceLeafPtr       `json:"list"`
	ByName  map[string]surfaceLeaf `json:"byName"`
	Maybe   *surfaceLeaf           `json:"maybe,omitempty"`
	Hidden  string                 `json:"-"`
	private string
	Untag   int
}

// TC-897-08: the walker reaches fields under a slice, a map value and a
// pointer, leaves out what is not on the wire, and sees a type change.
func TestWireSurfaceWalker(t *testing.T) {
	_ = surfaceFixture{}.private // referenced so the fixture's unexported field is not flagged unused
	_ = surfaceFixtureChanged{}.private
	got := wireSurface(reflect.TypeOf(surfaceFixture{}))
	for _, want := range []string{
		"list []tileschema.surfaceLeaf",
		"list[].flag bool",
		"byName map[string]tileschema.surfaceLeaf",
		"byName{}.flag bool",
		"maybe *tileschema.surfaceLeaf",
		"maybe.flag bool",
		"Untag int",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("surface lacks %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	for _, line := range got {
		if strings.Contains(line, "Hidden") || strings.Contains(line, "private") {
			t.Errorf("surface lists a field that is not on the wire: %q", line)
		}
	}
	if len(got) != 7 {
		t.Errorf("surface has %d lines, want 7:\n%s", len(got), strings.Join(got, "\n"))
	}
	changed := wireSurface(reflect.TypeOf(surfaceFixtureChanged{}))
	if slices.Equal(got, changed) {
		t.Error("changing list[].flag from bool to *bool did not change the surface")
	}
	if !slices.Contains(changed, "list[].flag *bool") {
		t.Errorf("changed surface lacks list[].flag *bool:\n%s", strings.Join(changed, "\n"))
	}
}
