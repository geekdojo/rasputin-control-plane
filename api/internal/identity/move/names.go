// Package move is Identity 5.1's identity.move (geekdojo/geekdojo-brain#1004):
// at the first start after the update, each pre-update operator is imported
// into the identity service under auth.MovedAccountID(handle), enabled, with
// app access user, the recovery-codes required action and no credential,
// and designated console admin and app admin (reason moved). The first to
// finish their setup becomes administrator unattended (C25); the rest wait
// for an administrator's grant. The same job runs again from a repair
// session in C9's state.
package move

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// maxName is the identity service's longest sign-in name
// (flows.UsernamePattern).
const maxName = 32

var usernameRE = regexp.MustCompile(flows.UsernamePattern)

// OldUser is a pre-update operator as the move reads it.
type OldUser struct {
	Handle      []byte
	Name        string
	DisplayName string
	CreatedAt   time.Time
}

// Mapping is one old operator's move: the account id it is moved to, and
// its old and new sign-in names.
type Mapping struct {
	User      OldUser
	AccountID string
	From, To  string
}

// validOld is the pre-update release's name rule: 1 to 32 characters of
// letters, digits, '_', '-' and '.', not starting with '-' or '.'.
func validOld(s string) bool {
	if len(s) < 1 || len(s) > maxName || s[0] == '-' || s[0] == '.' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// base is name under the rule before collisions: lowercased, a 'u' before
// a first character that is not a letter, "-1" after a one-character
// result, cut to 32 characters.
func base(name string) string {
	n := strings.ToLower(name)
	if n[0] < 'a' || n[0] > 'z' {
		n = "u" + n
	}
	if len(n) == 1 {
		n += "-1"
	}
	if len(n) > maxName {
		n = n[:maxName]
	}
	return n
}

// Map maps old to their new sign-in names, in created_at order with ties
// broken by handle bytes. taken holds the names already used in the realm
// by accounts that are not moved ones. A name already taken, by one
// mapped earlier or by taken, gets "-k" for the first free k from 2, its
// base cut to fit 32 characters. A name outside the old rule, or a result
// the identity service would refuse, is an error, and nothing is mapped.
func Map(old []OldUser, taken map[string]bool) ([]Mapping, error) {
	return mapKeeping(old, taken, nil)
}

// mapKeeping is Map where keep holds, by account id, the sign-in name an
// old operator already holds: the one its moved account has in the realm,
// or in repair mode the one its move row records. Such an operator keeps
// that name, and no other operator is mapped to it. An id in keep that is
// no old operator's is ignored.
func mapKeeping(old []OldUser, taken map[string]bool, keep map[string]string) ([]Mapping, error) {
	users := slices.Clone(old)
	slices.SortStableFunc(users, func(a, b OldUser) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return bytes.Compare(a.Handle, b.Handle)
	})
	used := make(map[string]bool, len(taken)+len(users))
	for n := range taken {
		used[strings.ToLower(n)] = true
	}
	for _, u := range users {
		if n, ok := keep[auth.MovedAccountID(u.Handle)]; ok {
			used[strings.ToLower(n)] = true
		}
	}
	out := make([]Mapping, 0, len(users))
	for i, u := range users {
		if len(u.Handle) == 0 {
			return nil, fmt.Errorf("move: old user %d has no handle", i)
		}
		if !validOld(u.Name) {
			return nil, fmt.Errorf("move: old user %d's name is outside the old rule", i)
		}
		id := auth.MovedAccountID(u.Handle)
		to, held := keep[id]
		if !held {
			b := base(u.Name)
			to = b
			for k := 2; used[to]; k++ {
				suf := "-" + strconv.Itoa(k)
				to = b[:min(len(b), maxName-len(suf))] + suf
			}
		}
		if !usernameRE.MatchString(to) {
			return nil, errors.New("move: a mapped name does not match the identity service's rule")
		}
		used[to] = true
		out = append(out, Mapping{User: u, AccountID: id, From: u.Name, To: to})
	}
	return out, nil
}
