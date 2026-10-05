package tsvreg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "reg.tsv")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var cols = []string{"path", "symbol", "reason"}

// TC-732-15: comments and blank lines are skipped; rows map column to value.
func TestRead_Rows(t *testing.T) {
	p := write(t, "# a comment\n\npath\tsymbol\treason\n# between\na.go\tT.M\tbecause\n\nb.go\tF\tso\n")
	rows, err := Read(p, cols)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{
		{"path": "a.go", "symbol": "T.M", "reason": "because"},
		{"path": "b.go", "symbol": "F", "reason": "so"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
}

// TC-732-15: every malformed register is an error that names the path.
func TestRead_Refusals(t *testing.T) {
	cases := map[string]string{
		"header column mismatch": "path\tsym\treason\n",
		"header column count":    "path\tsymbol\n",
		"row field count":        "path\tsymbol\treason\na.go\tT.M\n",
		"no header":              "# only a comment\n\n",
	}
	for name, body := range cases {
		p := write(t, body)
		_, err := Read(p, cols)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: error %q does not name %s", name, err, p)
		}
	}
	// The column is counted from 1, as a person reading the file counts it.
	if _, err := Read(write(t, "path\tsym\treason\n"), cols); err == nil || !strings.Contains(err.Error(), `header column 2 is "sym", want "symbol"`) {
		t.Errorf("header column mismatch: error %v does not name column 2", err)
	}
	missing := filepath.Join(t.TempDir(), "absent.tsv")
	if _, err := Read(missing, cols); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing file: error %v does not name %s", err, missing)
	}
}

// A row longer than bufio's 64 KiB default is read: the scanner accepts
// lines up to 1 MiB.
func TestRead_LongRow(t *testing.T) {
	long := strings.Repeat("x", 200*1024)
	rows, err := Read(write(t, "path\tsymbol\treason\na.go\tF\t"+long+"\n"), cols)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["reason"] != long {
		t.Fatalf("rows = %d, want the one long row intact", len(rows))
	}
}
