package converge

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// RequiredFeatures are the features the shipped build must run with
// (accounts-and-sign-in.md §12.1: passkeys, recovery codes, step-up,
// persistent sessions, client policies, and DPoP), by Keycloak's enum name.
var RequiredFeatures = []string{"PASSKEYS", "RECOVERY_CODES", "STEP_UP_AUTHENTICATION", "PERSISTENT_USER_SESSIONS", "CLIENT_POLICIES", "DPOP"}

const (
	serverInfoPath  = "/admin/serverinfo"
	disabledKey     = "features-disabled"
	unknownKeyLabel = "unknown:"
)

// featureKeyShape is one features-disabled entry.
var featureKeyShape = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// versionSuffix is a feature key's trailing -vN.
var versionSuffix = regexp.MustCompile(`-v[0-9]+$`)

// FeatureCheck compares the features the running identity service reports
// with the shipped build options (platform.md §2.3). Its verdict is cached
// per Keycloak run, so readings of the identity state do not each ask.
type FeatureCheck struct {
	admin    Admin
	readConf func() ([]byte, error)
	log      *slog.Logger

	mu         sync.Mutex
	invocation string // the run the cached verdict is for, "" for none
	mismatch   bool
}

// NewFeatureCheck checks its collaborators and returns a FeatureCheck.
// readConf reads the shipped keycloak-build.conf. It does no I/O.
func NewFeatureCheck(admin Admin, readConf func() ([]byte, error), log *slog.Logger) (*FeatureCheck, error) {
	if admin == nil || readConf == nil || log == nil {
		return nil, errors.New("converge: a features check collaborator is nil")
	}
	return &FeatureCheck{admin: admin, readConf: readConf, log: log.With("component", "identity")}, nil
}

// Mismatch reports whether the service, in its run kcInvocation, runs with
// features that differ from the build: a disabled feature reported enabled,
// a disabled key that names no feature, or a required feature absent or off.
// An unreadable or malformed conf, or a serverinfo read that fails, is an
// error, and is not cached. A verdict is cached for kcInvocation, unless it
// is empty (the units could not be read).
func (f *FeatureCheck) Mismatch(ctx context.Context, kcInvocation string) (bool, error) {
	f.mu.Lock()
	if kcInvocation != "" && kcInvocation == f.invocation {
		m := f.mismatch
		f.mu.Unlock()
		return m, nil
	}
	f.mu.Unlock()

	b, err := f.readConf()
	if err != nil {
		return false, fmt.Errorf("converge: read the shipped build options: %w", err)
	}
	disabled, err := parseBuildConf(b)
	if err != nil {
		return false, err
	}
	var info struct {
		Features []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"features"`
	}
	if _, err := f.admin.Admin(ctx, http.MethodGet, serverInfoPath, nil, &info); err != nil {
		return false, fmt.Errorf("converge: read the server's features: %w", err)
	}
	byKey := map[string][]bool{}
	byName := map[string]bool{}
	for _, ft := range info.Features {
		k := featureKey(ft.Name)
		byKey[k] = append(byKey[k], ft.Enabled)
		byName[ft.Name] = ft.Enabled
	}
	var wrong []string
	for _, k := range disabled {
		states, ok := byKey[k]
		if !ok {
			wrong = append(wrong, unknownKeyLabel+k)
			continue
		}
		if slices.Contains(states, true) {
			wrong = append(wrong, k)
		}
	}
	for _, name := range RequiredFeatures {
		if !byName[name] {
			wrong = append(wrong, name)
		}
	}
	mismatch := len(wrong) > 0
	if mismatch {
		f.log.LogAttrs(ctx, slog.LevelError, "The sign-in service is not running with the features this release built it with.",
			slog.String("event", "identity.features.mismatch"), slog.String("kc_invocation", kcInvocation), slog.Any("features", wrong))
	}
	if kcInvocation != "" {
		f.mu.Lock()
		f.invocation, f.mismatch = kcInvocation, mismatch
		f.mu.Unlock()
	}
	return mismatch, nil
}

// featureKey is the features-disabled key of a Keycloak feature enum name:
// lower-cased, _ replaced with -, and a trailing -vN dropped (ACCOUNT_V3 is
// account, ADMIN_FINE_GRAINED_AUTHZ_V2 is admin-fine-grained-authz).
func featureKey(name string) string {
	k := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	return versionSuffix.ReplaceAllString(k, "")
}

// parseBuildConf is the resolver for the shipped keycloak-build.conf: the
// keys its features-disabled line names (security-resolvers row R47). It
// fails closed: an empty file, a line that is not blank, a # comment or
// key=value, no features-disabled line or two of them, and an entry that is
// not a feature key are each an error.
func parseBuildConf(b []byte) ([]string, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("converge: the shipped build options are empty")
	}
	var keys []string
	seen := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("converge: build options line %d is not key=value", n)
		}
		if key != disabledKey {
			continue
		}
		if seen {
			return nil, fmt.Errorf("converge: build options name %s twice", disabledKey)
		}
		seen = true
		for _, k := range strings.Split(value, ",") {
			k = strings.TrimSpace(k)
			if !featureKeyShape.MatchString(k) {
				return nil, fmt.Errorf("converge: build options line %d has an entry that is not a feature key", n)
			}
			keys = append(keys, k)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("converge: read the build options: %w", err)
	}
	if !seen {
		return nil, fmt.Errorf("converge: the build options have no %s line", disabledKey)
	}
	return keys, nil
}
