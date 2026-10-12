package sealrotate

import (
	"fmt"
	"strings"
	"testing"
)

// TC-830-01: each shape renders to pinned bytes; #803's exact output parses
// as Clean; every other input is refused with an error naming the defect.
func TestFragment_RenderPinned(t *testing.T) {
	p := ProductionPaths()
	for _, tc := range []struct {
		f    Fragment
		want string
	}{
		{Fragment{Shape: Clean, Current: idA}, "seal \"static\" {\n" +
			"  current_key_id = \"" + string(idA) + "\"\n" +
			"  current_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n"},
		{Fragment{Shape: Staged, Current: idB, Previous: idA}, "seal \"static\" {\n" +
			"  current_key_id  = \"" + string(idB) + "\"\n" +
			"  current_key     = \"file:///run/credentials/openbao.service/seal-rotation_" + string(idB) + "\"\n" +
			"  previous_key_id = \"" + string(idA) + "\"\n" +
			"  previous_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n"},
		{Fragment{Shape: Verify, Current: idB}, "seal \"static\" {\n" +
			"  current_key_id = \"" + string(idB) + "\"\n" +
			"  current_key    = \"file:///run/credentials/openbao.service/seal-rotation_" + string(idB) + "\"\n}\n"},
	} {
		t.Run(tc.f.Shape.String(), func(t *testing.T) {
			got, err := tc.f.render(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("render =\n%s\nwant\n%s", got, tc.want)
			}
			back, err := parseFragment(p, got)
			if err != nil {
				t.Fatalf("its own render does not parse: %v", err)
			}
			if back != tc.f {
				t.Errorf("parse(render) = %+v, want %+v", back, tc.f)
			}
		})
	}
	if _, err := (Fragment{Shape: Staged, Current: idB}).render(p); err == nil {
		t.Error("a staged fragment with no previous id rendered")
	}
	if _, err := (Fragment{Shape: Shape(9), Current: idB}).render(p); err == nil {
		t.Error("an unknown shape rendered")
	}
}

// TC-830-01: rasputin-seal-key.sh's printf, byte for byte, is Clean with its
// key id.
func TestFragment_ParsesTheOneshotsOutput(t *testing.T) {
	b := fmt.Appendf(nil, "seal \"static\" {\n  current_key_id = \"%s\"\n  current_key    = \"%s\"\n}\n",
		idA, "file:///run/credentials/openbao.service/seal-key")
	f, err := parseFragment(ProductionPaths(), b)
	if err != nil {
		t.Fatal(err)
	}
	if f != (Fragment{Shape: Clean, Current: idA}) {
		t.Errorf("parsed %+v, want Clean %s", f, idA)
	}
}

// TC-830-01: the refusals.
func TestFragment_Refusals(t *testing.T) {
	clean := "seal \"static\" {\n  current_key_id = \"" + string(idA) + "\"\n  current_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n"
	for _, tc := range []struct{ name, in, defect string }{
		{"empty file", "", "is empty"},
		{"blank file", " \n\n", "is empty"},
		{"two seal blocks", clean + clean, "more than one seal block"},
		{"previous id without a previous key", strings.Replace(clean, "}\n",
			"  previous_key_id = \""+string(idB)+"\"\n}\n", 1), "previous key id without a previous key"},
		{"a key path outside the credentials directory", strings.Replace(clean,
			"/run/credentials/openbao.service/seal-key", "/var/lib/rasputin/openbao-seal/seal-key", 1), "not a credential"},
		{"no current_key_id", "seal \"static\" {\n  current_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n", "no current_key_id"},
		{"no current_key", "seal \"static\" {\n  current_key_id = \"" + string(idA) + "\"\n}\n", "no current_key"},
		{"another seal type", strings.Replace(clean, "static", "transit", 1), "does not open with a static seal block"},
		{"an unknown key", strings.Replace(clean, "}\n", "  disabled = \"true\"\n}\n", 1), "sets disabled"},
		{"a key set twice", strings.Replace(clean, "}\n", "  current_key_id = \""+string(idA)+"\"\n}\n", 1), "sets current_key_id twice"},
		{"an unquoted value", strings.Replace(clean, "\"file:///run/credentials/openbao.service/seal-key\"", "file", 1), "not key = \"value\""},
		{"an unclosed block", strings.TrimSuffix(clean, "}\n"), "not closed"},
		{"a bad key id", strings.Replace(clean, string(idA), "rasputin-../x", 1), "is not rasputin-<uuid>"},
		{"staged whose previous is the current", "seal \"static\" {\n  current_key_id  = \"" + string(idB) + "\"\n  current_key     = \"file:///run/credentials/openbao.service/seal-rotation_" + string(idB) + "\"\n  previous_key_id = \"" + string(idB) + "\"\n  previous_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n", "previous key id is its current one"},
		{"staged whose previous is not seal-key", "seal \"static\" {\n  current_key_id  = \"" + string(idB) + "\"\n  current_key     = \"file:///run/credentials/openbao.service/seal-rotation_" + string(idB) + "\"\n  previous_key_id = \"" + string(idA) + "\"\n  previous_key    = \"file:///run/credentials/openbao.service/seal-rotation_" + string(idA) + "\"\n}\n", "previous key is not the seal key"},
		{"staged with a bad previous id", "seal \"static\" {\n  current_key_id  = \"" + string(idB) + "\"\n  current_key     = \"file:///run/credentials/openbao.service/seal-rotation_" + string(idB) + "\"\n  previous_key_id = \"A\"\n  previous_key    = \"file:///run/credentials/openbao.service/seal-key\"\n}\n", "is not rasputin-<uuid>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFragment(ProductionPaths(), []byte(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.defect) {
				t.Fatalf("err = %v, want one naming %q", err, tc.defect)
			}
		})
	}
}

func TestShapeAndResumeNames(t *testing.T) {
	for _, tc := range [][2]string{
		{Clean.String(), "clean"}, {Staged.String(), "staged"}, {Verify.String(), "verify"}, {Shape(0).String(), "unknown"},
		{Fresh.String(), "fresh"}, {CleanUp.String(), "clean-up"}, {RewrapFirst.String(), "re-wrap-first"},
		{VerifyThenSettle.String(), "verify-then-settle"}, {Resume(0).String(), "unknown"},
	} {
		if tc[0] != tc[1] {
			t.Errorf("name = %q, want %q", tc[0], tc[1])
		}
	}
}
