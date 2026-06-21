package releases

import (
	"fmt"
	"regexp"
	"strconv"
)

// Scheme is the version-numbering convention a component uses. Rasputin has
// exactly two in the wild: CalVer for the OS + firewall images, semver for
// the control-plane software release.
type Scheme int

const (
	// SchemeCalVer parses YYYY.MM.PATCH with an optional -dev.N suffix, e.g.
	// "2026.06.0-dev.24" (pre-release) or "2026.07.1" (stable). A stable
	// release outranks any -dev of the same base; among -dev builds the
	// higher N is newer.
	SchemeCalVer Scheme = iota
	// SchemeSemver parses (v)MAJOR.MINOR.PATCH with an optional -dev.N
	// suffix, e.g. "v0.8.5" (stable) or "v0.8.7-dev.2" (pre-release). The
	// dev channel ships -dev.N pre-releases, so the suffix is significant:
	// a stable release outranks any -dev of the same base, and among -dev
	// builds the higher N is newer — same ordering as SchemeCalVer.
	SchemeSemver
)

var (
	calverRe = regexp.MustCompile(`^(\d{4})\.(\d{1,2})\.(\d+)(?:-dev\.(\d+))?$`)
	semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-dev\.(\d+))?$`)
)

// parsed is a comparable representation of a version under some scheme.
type parsed struct {
	parts  [3]int
	stable bool // CalVer only: true when there is no -dev suffix
	dev    int  // CalVer only: the -dev.N counter (0 when stable)
}

func parse(scheme Scheme, v string) (parsed, error) {
	switch scheme {
	case SchemeCalVer:
		m := calverRe.FindStringSubmatch(v)
		if m == nil {
			return parsed{}, fmt.Errorf("not a CalVer version: %q", v)
		}
		p := parsed{stable: m[4] == ""}
		for i := 0; i < 3; i++ {
			p.parts[i], _ = strconv.Atoi(m[i+1])
		}
		if !p.stable {
			p.dev, _ = strconv.Atoi(m[4])
		}
		return p, nil
	case SchemeSemver:
		m := semverRe.FindStringSubmatch(v)
		if m == nil {
			return parsed{}, fmt.Errorf("not a semver version: %q", v)
		}
		p := parsed{stable: m[4] == ""}
		for i := 0; i < 3; i++ {
			p.parts[i], _ = strconv.Atoi(m[i+1])
		}
		if !p.stable {
			p.dev, _ = strconv.Atoi(m[4])
		}
		return p, nil
	default:
		return parsed{}, fmt.Errorf("unknown version scheme %d", scheme)
	}
}

// Compare returns -1 if a<b, 0 if a==b, +1 if a>b, under the given scheme.
// Returns an error if either string doesn't parse.
func Compare(scheme Scheme, a, b string) (int, error) {
	pa, err := parse(scheme, a)
	if err != nil {
		return 0, err
	}
	pb, err := parse(scheme, b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if pa.parts[i] != pb.parts[i] {
			return sign(pa.parts[i] - pb.parts[i]), nil
		}
	}
	// Same base. A stable release outranks a -dev of the same base.
	if pa.stable != pb.stable {
		if pa.stable {
			return 1, nil
		}
		return -1, nil
	}
	if pa.dev != pb.dev {
		return sign(pa.dev - pb.dev), nil
	}
	return 0, nil
}

// IsNewer reports whether latest is strictly newer than installed. If either
// version is unparseable (e.g. a node that never reported its version, or a
// malformed tag), it returns false + the error so the caller can surface an
// "unknown" status rather than a false "update available".
func IsNewer(scheme Scheme, installed, latest string) (bool, error) {
	c, err := Compare(scheme, installed, latest)
	if err != nil {
		return false, err
	}
	return c < 0, nil
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
