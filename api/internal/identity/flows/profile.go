package flows

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// The sign-in name rule (C5): 2 to 32 characters, lowercase, starting with a
// letter (Headscale's floor).
const (
	UsernamePattern  = "^[a-z][a-z0-9._-]{1,31}$"
	usernameMin      = 2
	usernameMax      = 32
	usernameSentence = "A sign-in name is 2 to 32 lowercase letters, digits, dots, dashes or underscores, and starts with a letter."
	// displayNameFirst is how the profile shows firstName: the person's
	// one name field.
	displayNameFirst = "Name"
	claimPrefix      = "claim_"
)

// AdminOnlyAttributes are the user attributes only an administrator sees or
// edits, by name, with whether each holds more than one value: the app role,
// the network grants, the confirmed email and the five markers. The flows'
// conditions read them.
var AdminOnlyAttributes = map[string]bool{
	attrAppRole: false, attrNetwork: true, AttrConfirmedEmail: false,
	MarkerWebAuthnHome: false, MarkerWebAuthnApp: false,
	MarkerSecondStepHome: false, MarkerSecondStepApp: false, MarkerSecondStepAny: false,
}

// AttrConfirmedEmail is the confirmed email (geekdojo/geekdojo-brain#994):
// the address an administrator confirmed, which the rasputin-app-email
// client scope gives app tokens as email. The profile's own email is never
// given to apps.
const AttrConfirmedEmail = "rasputin_email"

// ProfileDiff is one owned part of the user profile that differs.
type ProfileDiff struct {
	Field     string
	Integrity bool
}

// keptUsernameValidators are Keycloak's own username validators, which the
// rules keep beside their length and pattern.
var keptUsernameValidators = []string{"username-prohibited-characters", "up-username-not-idn-homograph"}

func adminOnly() map[string]any {
	return map[string]any{"view": []any{"admin"}, "edit": []any{"admin"}}
}

func usernameValidations(observed map[string]any) map[string]any {
	v := map[string]any{
		"length":  map[string]any{"min": usernameMin, "max": usernameMax},
		"pattern": map[string]any{"pattern": UsernamePattern, "error-message": usernameSentence},
	}
	for _, k := range keptUsernameValidators {
		if c, ok := observed[k]; ok {
			v[k] = c
		} else {
			v[k] = map[string]any{}
		}
	}
	return v
}

// ApplyProfile applies the owned parts of the user profile to raw, the
// profile as read (GET /users/profile), keeping every other part as read.
// It returns the profile to write and the owned parts that differ; the
// profile is unchanged when diffs is empty. A claim_* attribute is checked
// for being admin-only, and repaired, but never created.
func ApplyProfile(raw []byte) (map[string]any, []ProfileDiff, error) {
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil, err
	}
	if p == nil {
		return nil, nil, errors.New("flows: the user profile is empty")
	}
	var diffs []ProfileDiff
	differ := func(field string, integrity bool) {
		diffs = append(diffs, ProfileDiff{Field: "profile." + field, Integrity: integrity})
	}
	if _, ok := p["unmanagedAttributePolicy"]; ok {
		differ("unmanagedAttributePolicy", false)
		delete(p, "unmanagedAttributePolicy")
	}
	attrs, _ := p["attributes"].([]any)
	var out []any
	seen := map[string]bool{}
	for _, a := range attrs {
		m, ok := a.(map[string]any)
		if !ok {
			out = append(out, a)
			continue
		}
		name, _ := m["name"].(string)
		seen[name] = true
		switch {
		case name == "lastName":
			differ("lastName", false)
			continue
		case name == "username":
			obs, _ := m["validations"].(map[string]any)
			if want := usernameValidations(obs); !SameJSON(obs, want) {
				differ("username.validations", false)
				m["validations"] = want
			}
		case name == "firstName":
			if m["displayName"] != displayNameFirst {
				differ("firstName.displayName", false)
				m["displayName"] = displayNameFirst
			}
		case strings.HasPrefix(name, claimPrefix):
			if !SameJSON(m["permissions"], adminOnly()) {
				differ("claim."+name, true)
				m["permissions"] = adminOnly()
			}
		default:
			if multi, owned := AdminOnlyAttributes[name]; owned {
				if !SameJSON(m["permissions"], adminOnly()) || m["multivalued"] != multi {
					differ("attribute."+name, true)
					m["permissions"], m["multivalued"] = adminOnly(), multi
				}
			}
		}
		out = append(out, m)
	}
	for _, name := range sortedKeys(AdminOnlyAttributes) {
		if !seen[name] {
			differ("attribute."+name, true)
			out = append(out, map[string]any{"name": name, "displayName": name, "permissions": adminOnly(),
				"multivalued": AdminOnlyAttributes[name]})
		}
	}
	p["attributes"] = out
	return p, diffs, nil
}

// SameJSON compares a and b by their JSON encoding, so numbers and slices
// read from JSON equal the ones written here.
func SameJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	var x, y any
	if json.Unmarshal(ja, &x) != nil || json.Unmarshal(jb, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
