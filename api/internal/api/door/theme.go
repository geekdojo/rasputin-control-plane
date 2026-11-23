package door

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
)

// KeycloakPin is the identity service release the theme's allowlist must be
// built for (identitytest's KeycloakRelease; a unit test holds the two
// equal).
const KeycloakPin = "26.8.2"

// The resource version's shape: Keycloak 26.8.2's resource tag, five
// characters of [0-9a-z] (MigrationModelAdapter's RESOURCE_TAG_LENGTH and
// RESOURCE_TAG_CHARSET; ThemeResource refuses any other segment).
const (
	resourceTagLength  = 5
	resourceTagCharset = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// validResourceVersion reports whether v has the resource tag's shape.
func validResourceVersion(v string) bool {
	if len(v) != resourceTagLength {
		return false
	}
	for i := range len(v) {
		if !strings.ContainsRune(resourceTagCharset, rune(v[i])) {
			return false
		}
	}
	return true
}

// themePaths are the two theme paths under version v that the doors serve
// and that the app door's script policy names.
func themePaths(v string) (login, common string) {
	return "/resources/" + v + "/login/rasputin/", "/resources/" + v + "/common/keycloak/"
}

// versionProbeFile is the theme file the version is read with: one the
// Rasputin login theme always serves (theme.properties' styles), with no
// content hash, so the identity service redirects it to the current version.
const versionProbeFile = "login/rasputin/css/tokens.css"

// VersionSource reads the running identity service's resource version:
// *idclient.Client's ResourceVersion.
type VersionSource interface {
	ResourceVersion(ctx context.Context, file string) (string, error)
}

// ResourceVersion is the resource version segment, /resources/<v>/, the
// running identity service serves its theme files under, as last learned
// (signin-origin.md §5.3, capability row K-CSP). Keycloak keeps <v> in each
// cluster's identity database and rewrites it when an upgrade migrates that
// database, so the doors learn it from the running service: once on each
// fact that it may have changed (Stale: the api's start, identitystate's
// BecameReady, and the service redirecting a theme file the door relayed),
// never on a timer. Until a value is known, and whenever the
// last read failed or answered a value without the tag's shape, it holds
// none, and the doors answer every /resources/ path with the 404 door page
// and name no theme path in a script policy. It is safe for concurrent use.
type ResourceVersion struct {
	src   VersionSource
	log   *slog.Logger
	stale chan struct{}
	v     atomic.Pointer[string]
}

// NewResourceVersion returns a holder with no version known. It does no I/O.
func NewResourceVersion(src VersionSource, log *slog.Logger) (*ResourceVersion, error) {
	switch {
	case src == nil:
		return nil, errors.New("door: the resource version's source is missing")
	case log == nil:
		return nil, errors.New("door: the resource version's logger is missing")
	}
	return &ResourceVersion{src: src, log: log.With("component", "signin-door"), stale: make(chan struct{}, 1)}, nil
}

// Current is the version known, if any.
func (r *ResourceVersion) Current() (string, bool) {
	if v := r.v.Load(); v != nil {
		return *v, true
	}
	return "", false
}

// Stale records a fact that the identity service's version may have
// changed: it has started or become ready, or it redirected a theme file
// asked for under the version held. Run reads it again. Facts made
// while a read runs coalesce into one more read. It never blocks.
func (r *ResourceVersion) Stale() {
	select {
	case r.stale <- struct{}{}:
	default:
	}
}

// Run learns the version once each time Stale is called, until ctx ends.
func (r *ResourceVersion) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stale:
			r.Learn(ctx)
		}
	}
}

// Learn reads the version from the identity service once. A value with the
// tag's shape replaces the one held; a failed read, or a value of any other
// shape, clears it, with one WARN record that never carries the value.
func (r *ResourceVersion) Learn(ctx context.Context) {
	v, err := r.src.ResourceVersion(ctx, versionProbeFile)
	switch {
	case err != nil:
		r.v.Store(nil)
		r.log.LogAttrs(ctx, slog.LevelWarn, "sign-in door resource version not read; theme files are refused until it is",
			slog.String("refused", "unreadable"), slog.String("err", err.Error()))
	case !validResourceVersion(v):
		r.v.Store(nil)
		r.log.LogAttrs(ctx, slog.LevelWarn, "sign-in door resource version refused: it is not a resource tag; theme files are refused until it is",
			slog.String("refused", "malformed"), slog.Int("length", len(v)))
	default:
		r.v.Store(&v)
		r.log.LogAttrs(ctx, slog.LevelInfo, "sign-in door resource version learned")
	}
}

// Allowlist is the built theme's resource-allowlist.json
// (ui/identity-theme/build.mjs, geekdojo/geekdojo-brain#988): the files under
// each theme path the doors may serve.
type Allowlist struct {
	login, common map[string]bool
}

// allows reports whether the door serves file under the login or the common
// theme path.
func (a Allowlist) allows(common bool, file string) bool {
	if common {
		return a.common[file]
	}
	return a.login[file]
}

// ParseAllowlist reads resource-allowlist.json. It refuses a file that does
// not parse, one built for another identity service release, one whose
// login list is empty, and any entry that is empty, absolute or climbs.
func ParseAllowlist(b []byte) (Allowlist, error) {
	var raw struct {
		Keycloak string   `json:"keycloak"`
		Login    []string `json:"login"`
		Common   []string `json:"common"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return Allowlist{}, fmt.Errorf("door: the theme allowlist does not parse: %w", err)
	}
	if raw.Keycloak != KeycloakPin {
		return Allowlist{}, fmt.Errorf("door: the theme allowlist is built for identity service %q, not %q", raw.Keycloak, KeycloakPin)
	}
	if len(raw.Login) == 0 {
		return Allowlist{}, errors.New("door: the theme allowlist lists no login file")
	}
	a := Allowlist{login: map[string]bool{}, common: map[string]bool{}}
	for _, l := range []struct {
		files []string
		into  map[string]bool
	}{{raw.Login, a.login}, {raw.Common, a.common}} {
		for _, f := range l.files {
			if f == "" || strings.HasPrefix(f, "/") || strings.Contains(f, "..") || strings.Contains(f, "\\") || strings.Contains(f, "%") {
				return Allowlist{}, fmt.Errorf("door: the theme allowlist holds the entry %q, which is not a plain relative path", f)
			}
			l.into[f] = true
		}
	}
	return a, nil
}
