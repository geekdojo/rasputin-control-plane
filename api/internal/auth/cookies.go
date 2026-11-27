package auth

import (
	"errors"
	"net/http"
	"time"
)

// The console's cookies (geekdojo/geekdojo-brain#989, signin-origin.md §5.3).
// Every one is a __Host- cookie: Secure, Path=/ and no Domain, so it is
// bound to the console's own origin, and HttpOnly and SameSite=Lax, so the
// identity service's cross-site redirect back to the callback (SO-18) still
// carries it and no script reads it.
const (
	// SessionCookieName is the console session.
	SessionCookieName = "__Host-rasputin-session"
	// pendingCookieName names a sign-in in flight (pending.go).
	pendingCookieName = "__Host-rasputin-pending"
)

// errNoCookie and errDuplicateCookie are oneCookie's refusals.
var (
	errNoCookie        = errors.New("auth: cookie absent")
	errDuplicateCookie = errors.New("auth: cookie sent twice")
)

// duplicateCookieBody is the 400 a request carrying two cookies of one name
// gets: a browser never sends that for the api's own __Host- cookies, so it
// is a cookie planted by another site, and the request is refused rather
// than guessing which copy is the console's.
func duplicateCookieBody(name string) map[string]string {
	return map[string]string{
		"error":  "duplicate_cookie",
		"detail": "The request carried the " + name + " cookie more than once. Clear this site's cookies and sign in again.",
	}
}

// oneCookie returns the one cookie named name: errNoCookie when there is
// none, errDuplicateCookie when there are two or more.
func oneCookie(r *http.Request, name string) (*http.Cookie, error) {
	found := r.CookiesNamed(name)
	switch len(found) {
	case 0:
		return nil, errNoCookie
	case 1:
		return found[0], nil
	}
	return nil, errDuplicateCookie
}

// writeDuplicateCookie answers the duplicate-cookie refusal.
func writeDuplicateCookie(w http.ResponseWriter, name string) {
	writeJSON(w, http.StatusBadRequest, duplicateCookieBody(name))
}

// setCookie is the one writer of the console's cookies: value for maxAge.
func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearCookie expires the cookie named name.
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
