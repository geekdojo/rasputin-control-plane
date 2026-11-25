package move

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

func old(h byte, name string, created int64) OldUser {
	handle := make([]byte, 16)
	handle[15] = h
	return OldUser{Handle: handle, Name: name, CreatedAt: time.Unix(created, 0)}
}

// TC-1004-03: the mapping table, in created_at order with ties broken by
// handle bytes; deterministic over permutations; every output matches the
// identity service's rule; invalid inputs are errors.
func TestMap_TC1004_03(t *testing.T) {
	valid32 := "abcdefghij0123456789abcdefghij01"
	digit32 := "9" + valid32[1:]
	users := []OldUser{
		old(1, "b", 10),
		old(2, "9lives", 20),
		old(3, "_x", 30),
		old(4, "Bryce", 40),   // older: keeps bryce
		old(5, "bryce-2", 45), // an old user literally named bryce-2
		old(6, "bryce", 50),   // the later collision: -2 is taken, so -3
		old(7, valid32, 60),
		old(8, digit32, 70),
		old(9, "door", 80), // the realm's door account holds door
		// A 32-character name colliding with valid32 once lowercased: the
		// base is cut to fit the suffix.
		old(10, strings.ToUpper(valid32[:1])+valid32[1:], 95),
	}
	taken := map[string]bool{"door": true}
	want := map[string]string{
		"b": "b-1", "9lives": "u9lives", "_x": "u_x", "Bryce": "bryce", "bryce-2": "bryce-2", "bryce": "bryce-3",
		valid32: valid32, digit32: "u" + digit32[:31], "door": "door-2",
		strings.ToUpper(valid32[:1]) + valid32[1:]: valid32[:30] + "-2",
	}
	re := regexp.MustCompile(flows.UsernamePattern)
	got, err := Map(users, taken)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d mappings, want %d", len(got), len(want))
	}
	for _, m := range got {
		if m.To != want[m.From] {
			t.Errorf("%s -> %s, want %s", m.From, m.To, want[m.From])
		}
		if !re.MatchString(m.To) || len(m.To) > 32 {
			t.Errorf("%s does not match %s", m.To, flows.UsernamePattern)
		}
		if m.AccountID != auth.MovedAccountID(m.User.Handle) {
			t.Errorf("%s: account id %s, want MovedAccountID", m.From, m.AccountID)
		}
	}
	// Determinism: any order of the same users gives the same output.
	for range 20 {
		shuffled := append([]OldUser(nil), users...)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, err := Map(shuffled, taken)
		if err != nil {
			t.Fatal(err)
		}
		for i := range got {
			if again[i].From != got[i].From || again[i].To != got[i].To {
				t.Fatalf("a permutation changed position %d: %s->%s, want %s->%s", i, again[i].From, again[i].To, got[i].From, got[i].To)
			}
		}
	}
	// Ties on created_at break by handle bytes.
	tie, err := Map([]OldUser{old(2, "Same", 1), old(1, "same", 1)}, nil)
	if err != nil || tie[0].From != "same" || tie[0].To != "same" || tie[1].To != "same-2" {
		t.Errorf("tie: %+v %v, want the lower handle first", tie, err)
	}
	for _, bad := range []string{"", "-x", ".x", "has space", "ünï", strings.Repeat("a", 33)} {
		if _, err := Map([]OldUser{old(1, bad, 1)}, nil); err == nil {
			t.Errorf("Map(%q) succeeded, want an error", bad)
		}
	}
	if _, err := Map([]OldUser{{Name: "nohandle"}}, nil); err == nil {
		t.Error("Map with no handle succeeded")
	}
}
