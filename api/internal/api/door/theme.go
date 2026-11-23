package door

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ResourceVersion is the resource version segment the pinned identity
// service serves its theme files under, /resources/<v>/ (Keycloak 26.8.2's
// build; capability row K-CSP records it, and CI asserts the live server
// serves it). A pin bump changes it and the row together.
const ResourceVersion = "xmkpe"

// KeycloakPin is the identity service release the theme's allowlist must be
// built for (identitytest's KeycloakRelease; a unit test holds the two
// equal).
const KeycloakPin = "26.8.2"

// The theme paths the doors serve, and that the app door's script policy
// names.
const (
	themeLoginPath  = "/resources/" + ResourceVersion + "/login/rasputin/"
	themeCommonPath = "/resources/" + ResourceVersion + "/common/keycloak/"
)

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
