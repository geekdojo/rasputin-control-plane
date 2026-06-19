package releases

import "testing"

func TestCompareCalVer(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2026.06.0-dev.23", "2026.06.0-dev.24", -1}, // higher dev.N is newer
		{"2026.06.0-dev.24", "2026.06.0-dev.23", 1},
		{"2026.06.0-dev.24", "2026.06.0-dev.24", 0},
		{"2026.06.0", "2026.06.0-dev.24", 1},  // stable outranks dev of same base
		{"2026.06.0-dev.24", "2026.06.0", -1}, // and vice-versa
		{"2026.06.0", "2026.06.0", 0},
		{"2026.07.1-dev.15", "2026.07.0", 1}, // newer base beats stable of older base
		{"2026.06.0", "2026.07.0", -1},       // month
		{"2025.12.0", "2026.01.0", -1},       // year
	}
	for _, c := range cases {
		got, err := Compare(SchemeCalVer, c.a, c.b)
		if err != nil {
			t.Fatalf("Compare(%q,%q) error: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.8.4", "v0.8.5", -1},
		{"v0.8.5", "v0.8.5", 0},
		{"v0.9.0", "v0.8.5", 1},
		{"v1.0.0", "v0.99.99", 1},
		{"0.8.5", "v0.8.5", 0}, // leading v optional
	}
	for _, c := range cases {
		got, err := Compare(SchemeSemver, c.a, c.b)
		if err != nil {
			t.Fatalf("Compare(%q,%q) error: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if newer, err := IsNewer(SchemeCalVer, "2026.06.0-dev.23", "2026.06.0-dev.24"); err != nil || !newer {
		t.Errorf("expected newer, got newer=%v err=%v", newer, err)
	}
	if newer, _ := IsNewer(SchemeCalVer, "2026.06.0-dev.24", "2026.06.0-dev.24"); newer {
		t.Errorf("equal versions should not be newer")
	}
	if _, err := IsNewer(SchemeCalVer, "garbage", "2026.06.0"); err == nil {
		t.Errorf("expected parse error for unparseable installed version")
	}
}
