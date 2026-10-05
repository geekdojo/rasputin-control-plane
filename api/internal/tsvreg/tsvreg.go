// Package tsvreg reads the repo's tab-separated registers: the files under
// .github/ that record a reviewed verdict per finding (failopen-allow.tsv,
// security-resolvers.tsv, secret-reveal-allow.tsv). One reader, so the lints
// that hold those registers cannot disagree about what a well-formed one is.
package tsvreg

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Read reads a tab-separated register with a '#' comment convention and a
// header naming every column, and refuses a header that does not match.
func Read(path string, cols []string) ([]map[string]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Read-only: nothing is buffered, so a close error carries no
	// information this command could act on.
	defer func() { _ = fh.Close() }()

	var out []map[string]string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	header := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if !header {
			if len(parts) != len(cols) {
				return nil, fmt.Errorf("%s: header has %d columns, want %d (%s)",
					path, len(parts), len(cols), strings.Join(cols, ", "))
			}
			for i, c := range cols {
				if parts[i] != c {
					return nil, fmt.Errorf("%s: header column %d is %q, want %q", path, i+1, parts[i], c)
				}
			}
			header = true
			continue
		}
		if len(parts) != len(cols) {
			return nil, fmt.Errorf("%s: a row has %d fields, want %d", path, len(parts), len(cols))
		}
		row := map[string]string{}
		for i, c := range cols {
			row[c] = parts[i]
		}
		out = append(out, row)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !header {
		return nil, fmt.Errorf("%s: no header row", path)
	}
	return out, nil
}
