package quiesce

import "testing"

// markerName sanitises an app id into a marker file name: [A-Za-z0-9_-] pass
// through verbatim, every other rune becomes '_', an empty result becomes
// "app", and ".json" is appended. The character-class switch (watchdog.go) is
// the load-bearing part — a marker whose name escaped the app-id charset could
// name a file outside the marker dir — so pin each end of every accepted range
// and prove the reject path maps the rest to '_'.
func TestMarkerName(t *testing.T) {
	// Every boundary of every accepted class, in one string: a/z, A/Z, 0/9,
	// '-' and '_'. A mutation that shifts any bound (e.g. `r >= 'a'` → `r > 'a'`)
	// drops that char to '_', so the whole string stops round-tripping.
	if got := markerName("azAZ09-_"); got != "azAZ09-_.json" {
		t.Errorf("markerName(%q) = %q, want %q — an accepted-charset boundary was lost",
			"azAZ09-_", got, "azAZ09-_.json")
	}

	// The reject path: characters outside the class must all collapse to '_'.
	// A negated class test (e.g. `r == '-'` → `r != '-'`) would instead let a
	// '.' or '/' pass through verbatim, so asserting they are replaced kills it.
	if got := markerName("a.b/c:d"); got != "a_b_c_d.json" {
		t.Errorf("markerName(%q) = %q, want %q — a disallowed rune was not mapped to '_'",
			"a.b/c:d", got, "a_b_c_d.json")
	}

	// A name that sanitises to nothing falls back to "app" rather than a bare
	// ".json".
	if got := markerName(""); got != "app.json" {
		t.Errorf("markerName(%q) = %q, want %q", "", got, "app.json")
	}
	if got := markerName("你好"); got != "__.json" {
		t.Errorf("markerName(%q) = %q, want %q — non-ASCII runes each map to one '_'",
			"你好", got, "__.json")
	}
}
