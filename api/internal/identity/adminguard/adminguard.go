// Package adminguard is the doors' admin-account guard: it refuses, before
// anything reaches the identity service, any request that names the api's
// own Admin API client (rasputin-admin) or its service-account user
// (geekdojo/geekdojo-brain#1127, Identity 2.8).
//
// Keycloak counts a login failure against a user only when a request names
// that user in its form, in Basic credentials, or the user is already
// authenticated. Its brute-force protection would lock the service account
// after failureFactor such failures. Refusing every request whose query or
// form values, or Basic user, name the account means nothing outside the
// control plane can drive that count.
//
// It is pure: no I/O beyond the request it is handed, no clock, no logger and
// no randomness. The door's policy service (Identity 4.3,
// geekdojo/geekdojo-brain#985) calls FromRequest and Check before it forwards
// anything; the identitytest front, which stands in for the door, calls them
// today.
package adminguard

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

const (
	// AdminClientID is the realm baseline's Admin API client, the one the
	// api's session logs in as (C27, C28).
	AdminClientID = "rasputin-admin"
	// ServiceAccountUsername is AdminClientID's service-account user, by
	// Keycloak's naming, and the baseline's one user.
	ServiceAccountUsername = "service-account-" + AdminClientID
)

var (
	// ErrAdminAccount is a request naming AdminClientID or
	// ServiceAccountUsername.
	ErrAdminAccount = errors.New("adminguard: the request names the api's admin account")
	// ErrUnreadable is a request the guard cannot read, so cannot clear: a
	// bad escape, a body that is not a url-encoded POST, more than one
	// Authorization header, or a Basic credential that does not decode.
	ErrUnreadable = errors.New("adminguard: the request could not be read")
)

// The person-facing sentences (ERR-MESSAGE).
const (
	adminAccountSentence = "This account can't sign in here. Sign in with your own account."
	unreadableSentence   = "This sign-in request couldn't be read. Start signing in again."
)

// Input is a request as the guard reads it: its query, its url-encoded body
// and its one Authorization header, each kept apart.
type Input struct {
	Query, Form   url.Values
	Authorization string
}

// FromRequest reads r into an Input. It returns ErrUnreadable for a query
// url.ParseQuery rejects; a request with a body that is not a POST of
// application/x-www-form-urlencoded; a form r.ParseForm rejects; or more
// than one Authorization header. Otherwise it puts the re-encoded form back
// as r's body, so r can be forwarded. The path is never read.
func FromRequest(r *http.Request) (Input, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return Input{}, ErrUnreadable
	}
	auth := r.Header.Values("Authorization")
	if len(auth) > 1 {
		return Input{}, ErrUnreadable
	}
	in := Input{Query: query, Form: url.Values{}}
	if len(auth) == 1 {
		in.Authorization = auth[0]
	}
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return in, nil
	}
	if r.Method != http.MethodPost {
		return Input{}, ErrUnreadable
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return Input{}, ErrUnreadable
	}
	if err := r.ParseForm(); err != nil {
		return Input{}, ErrUnreadable
	}
	in.Form = r.PostForm
	body := in.Form.Encode()
	r.Body = io.NopCloser(strings.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	return in, nil
}

// Check returns ErrAdminAccount when any query or form value, whatever its
// parameter's name, or the user of a Basic Authorization names the admin
// account; ErrUnreadable when a Basic credential does not decode; and nil
// otherwise. A value is trimmed and compared case-insensitively, a superset
// of Keycloak's own trim and lower-cased lookup.
func Check(in Input) error {
	for _, vals := range []url.Values{in.Query, in.Form} {
		for _, vs := range vals {
			for _, v := range vs {
				if names(v) {
					return ErrAdminAccount
				}
			}
		}
	}
	user, ok, err := BasicUser(in.Authorization)
	if err != nil {
		return err
	}
	if ok && names(user) {
		return ErrAdminAccount
	}
	return nil
}

// Sentence is the person-facing sentence for an error FromRequest or Check
// returned: what happened and what to do. Any error other than
// ErrAdminAccount reads as unreadable.
func Sentence(err error) string {
	if errors.Is(err, ErrAdminAccount) {
		return adminAccountSentence
	}
	return unreadableSentence
}

// BasicUser is the user of a Basic Authorization, base64-decoded strictly
// and then URL-decoded, as Keycloak's BasicAuthHelper reads it (RFC 6749
// §2.3.1). ok is false for no header or another scheme; a credential that
// does not decode is ErrUnreadable. The door reads the client a token call
// names through it (geekdojo/geekdojo-brain#985).
func BasicUser(header string) (user string, ok bool, err error) {
	scheme, cred, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return "", false, ErrUnreadable
	}
	user, _, _ = strings.Cut(string(raw), ":")
	if user, err = url.QueryUnescape(user); err != nil {
		return "", false, ErrUnreadable
	}
	return user, true, nil
}

// names reports whether v, trimmed of control characters and Unicode spaces,
// is either admin-account name in any case.
func names(v string) bool {
	v = strings.TrimFunc(v, func(r rune) bool { return r <= ' ' || unicode.IsSpace(r) })
	return strings.EqualFold(v, AdminClientID) || strings.EqualFold(v, ServiceAccountUsername)
}
