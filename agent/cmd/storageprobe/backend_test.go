package main

import (
	"errors"
	"strings"
	"testing"
)

// selectBackend is the one function in this command that can turn every other
// line of its output into fiction, so it gets the table.
func TestSelectBackend(t *testing.T) {
	completeTooling := []string(nil)
	missingWipefs := []string{"wipefs"}

	tests := []struct {
		name        string
		choice      string
		missing     []string
		wantName    string
		wantFixture bool
		wantErr     error
		// wantDetail is a substring the refusal must name. The point of
		// MissingTools returning names rather than a bool is that the operator
		// is told which package to add to the image; a refusal that loses that
		// is the bool again.
		wantDetail string
	}{
		{
			name:   "no choice and complete tooling is the real backend",
			choice: "", missing: completeTooling,
			wantName: "blockdev",
		},
		{
			name:   "blockdev by name and complete tooling is the real backend",
			choice: "blockdev", missing: completeTooling,
			wantName: "blockdev",
		},
		{
			// The 2026-09-01 incident, as an assertion. Autodetect must refuse
			// rather than reach for the mock, whose fixture disks are
			// indistinguishable from a real answer.
			name:   "no choice and missing tooling REFUSES and never falls back to the mock",
			choice: "", missing: missingWipefs,
			wantErr: errNoTooling, wantDetail: "wipefs",
		},
		{
			// Asking for the real backend by name does not conjure the tool.
			name:   "blockdev by name and missing tooling refuses too",
			choice: "blockdev", missing: missingWipefs,
			wantErr: errNoTooling, wantDetail: "wipefs",
		},
		{
			name:   "the refusal names every missing tool, not just the first",
			choice: "", missing: []string{"wipefs", "sfdisk", "mkfs.ext4"},
			wantErr: errNoTooling, wantDetail: "sfdisk",
		},
		{
			// The only way to the mock, and it stays available even where the
			// real backend would work: a dev laptop with util-linux installed
			// must still be able to ask for fixtures.
			name:   "mock is reachable only by name",
			choice: "mock", missing: completeTooling,
			wantName: "mock", wantFixture: true,
		},
		{
			name:   "mock by name on a machine with no tooling is still the mock",
			choice: "mock", missing: missingWipefs,
			wantName: "mock", wantFixture: true,
		},
		{
			name:   "whitespace around a choice does not change it",
			choice: "  mock  ", missing: completeTooling,
			wantName: "mock", wantFixture: true,
		},
		{
			// Not a storage failure: a typo must not be readable as one.
			name:   "an unknown backend is a usage error",
			choice: "moc", missing: completeTooling,
			wantErr: errBadBackend,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectBackend(tc.choice, tc.missing)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("selectBackend(%q, %v) error = %v, want %v", tc.choice, tc.missing, err, tc.wantErr)
				}
				if tc.wantDetail != "" && !strings.Contains(err.Error(), tc.wantDetail) {
					t.Errorf("refusal does not name %q: %v", tc.wantDetail, err)
				}
				if got.Name != "" {
					t.Errorf("a refusal still resolved a backend: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectBackend(%q, %v) = %v", tc.choice, tc.missing, err)
			}
			if got.Name != tc.wantName || got.Fixture != tc.wantFixture {
				t.Errorf("selectBackend(%q, %v) = %+v, want {Name:%q Fixture:%t}",
					tc.choice, tc.missing, got, tc.wantName, tc.wantFixture)
			}
		})
	}
}

// The property the table above is really protecting, asserted directly so it
// survives someone rewriting the cases: no value of `missing` can make an
// empty choice resolve to the mock.
func TestSelectBackend_AutodetectNeverYieldsTheMock(t *testing.T) {
	for _, missing := range [][]string{
		nil,
		{},
		{"wipefs"},
		{"lsblk", "blkid", "wipefs", "sfdisk", "mkfs.ext4", "mount", "umount"},
	} {
		got, err := selectBackend("", missing)
		if err != nil {
			continue // refused, which is the other acceptable answer
		}
		if got.Fixture || got.Name == "mock" {
			t.Fatalf("selectBackend(\"\", %v) autodetected the mock: %+v", missing, got)
		}
	}
}
