package sealrotate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-830-03: each recognised tree maps to its state and resume action; each
// unrecognised tree is an error; State changes nothing.
func TestFiles_State(t *testing.T) {
	for _, tc := range []struct {
		name      string
		build     func(s *seal)
		shape     Shape
		resume    Resume
		leftovers []string
		defect    string // set for an unrecognised tree
	}{
		{name: "clean", build: func(s *seal) { s.clean() }, shape: Clean, resume: Fresh},
		{name: "clean with a leftover rotation/B", build: func(s *seal) { s.clean().rot(idB, keyB) },
			shape: Clean, resume: CleanUp, leftovers: []string{string(idB)}},
		{name: "clean with an atrest temp file in rotation/", build: func(s *seal) {
			s.clean().rot(KeyID("."+string(idB)+".123.tmp"), keyB[:10])
		}, shape: Clean, resume: CleanUp, leftovers: []string{"." + string(idB) + ".123.tmp"}},
		{name: "staged", build: func(s *seal) {
			s.clean().rot(idB, keyB)
			s.fragment(Fragment{Shape: Staged, Current: idB, Previous: idA})
		}, shape: Staged, resume: RewrapFirst},
		{name: "verify with seal-key A", build: func(s *seal) {
			s.clean().rot(idB, keyB)
			s.fragment(Fragment{Shape: Verify, Current: idB})
		}, shape: Verify, resume: VerifyThenSettle},
		{name: "verify with seal-key B", build: func(s *seal) {
			s.clean().rot(idB, keyB)
			s.write(SealKeyName, keyB)
			s.fragment(Fragment{Shape: Verify, Current: idB})
		}, shape: Verify, resume: VerifyThenSettle},

		{name: "seal-key 31 bytes", build: func(s *seal) { s.clean().write(SealKeyName, keyA[:31]) }, defect: "is 31 bytes"},
		{name: "rotation/B 33 bytes", build: func(s *seal) {
			s.clean().rot(idB, append(append([]byte{}, keyB...), 0))
			s.fragment(Fragment{Shape: Staged, Current: idB, Previous: idA})
		}, defect: "is 33 bytes"},
		{name: "staged naming an absent rotation/<id>", build: func(s *seal) {
			s.clean()
			s.fragment(Fragment{Shape: Staged, Current: idB, Previous: idA})
		}, defect: "rotation/ holds 0 entries"},
		{name: "two files in rotation/", build: func(s *seal) {
			s.clean().rot(idB, keyB)
			s.rot(idA, keyA)
			s.fragment(Fragment{Shape: Staged, Current: idB, Previous: idA})
		}, defect: "rotation/ holds 2 entries"},
		{name: "an unreadable fragment", build: func(s *seal) {
			s.clean()
			if err := os.Remove(filepath.Join(s.dir, FragmentName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(s.dir, FragmentName), 0o700); err != nil {
				t.Fatal(err)
			}
		}, defect: "read the seal fragment"},
		{name: "seal-key missing", build: func(s *seal) {
			s.clean()
			if err := os.Remove(filepath.Join(s.dir, SealKeyName)); err != nil {
				t.Fatal(err)
			}
		}, defect: "seal key"},
		{name: "seal-key a directory", build: func(s *seal) {
			s.fragment(Fragment{Shape: Clean, Current: idA})
			if err := os.Mkdir(filepath.Join(s.dir, SealKeyName), 0o700); err != nil {
				t.Fatal(err)
			}
		}, defect: "not a regular file"},
		{name: "rotation/ missing", build: func(s *seal) {
			s.clean()
			if err := os.Remove(filepath.Join(s.dir, RotationDirName)); err != nil {
				t.Fatal(err)
			}
		}, defect: "list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSeal(t)
			tc.build(s)
			before := s.hash()
			tree, err := s.files.State()
			if after := s.hash(); after != before {
				t.Fatal("State changed the seal tree")
			}
			if tc.defect != "" {
				if err == nil || !strings.Contains(err.Error(), tc.defect) {
					t.Fatalf("State = %+v, %v; want an error naming %q", tree, err, tc.defect)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tree.Fragment.Shape != tc.shape || tree.Resume != tc.resume {
				t.Errorf("State = %s/%s, want %s/%s", tree.Fragment.Shape, tree.Resume, tc.shape, tc.resume)
			}
			if strings.Join(tree.Leftovers, ",") != strings.Join(tc.leftovers, ",") {
				t.Errorf("leftovers = %v, want %v", tree.Leftovers, tc.leftovers)
			}
		})
	}
}

// TC-830-03, F-830-06: State sizes key files by Lstat and never opens them: a
// key made unreadable, at its right size, still classifies.
func TestFiles_StateNeverReadsKeys(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 file, so unreadability proves nothing here")
	}
	s := newSeal(t)
	s.clean().rot(idB, keyB)
	s.fragment(Fragment{Shape: Staged, Current: idB, Previous: idA})
	for _, rel := range []string{SealKeyName, filepath.Join(RotationDirName, string(idB))} {
		p := filepath.Join(s.dir, rel)
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		if _, err := os.ReadFile(p); err == nil {
			t.Fatal("a mode-0000 file is still readable here")
		}
	}
	if tree := s.state(); tree.Fragment.Shape != Staged || tree.Resume != RewrapFirst {
		t.Errorf("State = %+v, want Staged / re-wrap-first", tree)
	}
}

// The writes go through atrest at 0600, the read-back returns exactly the key
// and zeroes its buffer, and a wrong-sized key is refused.
func TestFiles_KeyRoundTrip(t *testing.T) {
	s := newSeal(t)
	s.clean()
	var bufs [][]byte
	s.files.newBuf = func(n int) []byte { b := make([]byte, n); bufs = append(bufs, b); return b }

	key := secret.New(keyB)
	if err := s.files.WriteRotationKey(idB, key); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(s.dir, RotationDirName, string(idB)))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("rotation/B mode = %v, %v; want 0600", fi.Mode(), err)
	}
	back, err := s.files.ReadRotationKey(idB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Reveal(), keyB) {
		t.Fatal("the read-back key differs")
	}
	if err := s.files.WriteSealKey(back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.read(SealKeyName), keyB) {
		t.Fatal("seal-key does not hold the key written")
	}
	for _, b := range bufs {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error("the read-back buffer was not zeroed")
		}
	}
	if err := s.files.WriteSealKey(secret.New(keyA[:31])); err == nil {
		t.Error("a 31-byte key was written")
	}
	s.rot(idA, append(append([]byte{}, keyA...), 1))
	if _, err := s.files.ReadRotationKey(idA); err == nil || !strings.Contains(err.Error(), "more than 32") {
		t.Errorf("a 33-byte key read back: %v", err)
	}
	s.rot(idA, keyA[:5])
	if _, err := s.files.ReadRotationKey(idA); err == nil {
		t.Error("a 5-byte key read back")
	}
	if _, err := s.files.ReadRotationKey("rasputin-cccccccc-cccc-4ccc-8ccc-cccccccccccc"); err == nil {
		t.Error("an absent key read back")
	}
	if err := s.files.RemoveRotation(); err != nil {
		t.Fatal(err)
	}
	if names := s.rotationNames(); len(names) != 0 {
		t.Errorf("rotation/ = %v after RemoveRotation", names)
	}
	if err := s.files.WriteFragment(Fragment{Shape: Staged, Current: idB}); err == nil {
		t.Error("a staged fragment with no previous was written")
	}
}

func TestNewFiles_Refuses(t *testing.T) {
	for _, p := range []Paths{
		{CredDir: "c", RotationCred: ProductionPaths().RotationCred},
		{SealDir: "s", RotationCred: ProductionPaths().RotationCred},
		{SealDir: "s", CredDir: "c"},
	} {
		if _, err := NewFiles(p); err == nil {
			t.Errorf("NewFiles(%+v) accepted", p)
		}
	}
}
