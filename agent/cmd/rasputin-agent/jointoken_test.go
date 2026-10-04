package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/logkit"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-539-07: the agent's join-token startup record goes through the injected
// logger as one structured record at a level, and carries no token.
//
// Each case resolves through bus.ResolveTokenSource exactly as main does, so
// the record is checked against the description the resolver really produces.
// A token string is written to the file the resolver reads and placed in the
// test's scope; it must never reach the buffer.
func TestLogJoinTokenSource(t *testing.T) {
	const testToken = "tc-539-07-secret-token-value"
	dir := t.TempDir()
	file := filepath.Join(dir, "join.token")
	if err := os.WriteFile(file, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		file      string
		legacySet bool
		wantLevel string
		wantMsg   string
		// wantFields are key=value substrings the record must carry.
		wantFields []string
		// wantRetired: the record must (true) or must not (false) name the
		// retired variable on its own.
		wantRetired bool
	}{
		{"none, the retired variable set", "", true, "ERROR", "no bus join token",
			[]string{"retired_variable_set=true", `fix="put the token in a 0600 file named by ` + bus.EnvJoinTokenFile + `"`, "no longer read"}, true},
		{"none, the retired variable unset", "", false, "ERROR", "no bus join token",
			[]string{"retired_variable_set=false", `fix="put the token in a 0600 file named by ` + bus.EnvJoinTokenFile + `"`}, false},
		{"a file, the retired variable set", file, true, "WARN", bus.EnvJoinToken + " is set and not read; the token file is used",
			[]string{"source=", bus.EnvJoinTokenFile}, true},
		{"a file, the retired variable unset", file, false, "INFO", "bus join token source",
			[]string{"source=", bus.EnvJoinTokenFile}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, describe, none := bus.ResolveTokenSource(tc.file, tc.legacySet, proto.RoleCompute, filepath.Join(dir, "unused.token"))
			logJoinTokenSource(logkit.New(&buf), describe, none, tc.legacySet)

			out := buf.String()
			lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("want exactly one record, got %d:\n%s", len(lines), out)
			}
			rec := lines[0]
			if !strings.Contains(rec, "level="+tc.wantLevel+" ") {
				t.Errorf("record %q: want level=%s", rec, tc.wantLevel)
			}
			if !strings.Contains(rec, tc.wantMsg) {
				t.Errorf("record %q: want message %q", rec, tc.wantMsg)
			}
			for _, f := range tc.wantFields {
				if !strings.Contains(rec, f) {
					t.Errorf("record %q: want %q", rec, f)
				}
			}
			named := strings.Contains(strings.ReplaceAll(rec, bus.EnvJoinTokenFile, ""), bus.EnvJoinToken)
			if named != tc.wantRetired {
				t.Errorf("record %q names %s = %v, want %v", rec, bus.EnvJoinToken, named, tc.wantRetired)
			}
			if strings.Contains(out, testToken) {
				t.Errorf("record carries the token: %q", rec)
			}
		})
	}
}
