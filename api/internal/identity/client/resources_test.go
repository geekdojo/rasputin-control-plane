package idclient

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// TC-985-47 and TC-985-48, the source half: the probe asks the theme
// endpoint for the file under a placeholder version and reads <v> from the
// redirect, as Keycloak 26.8.2's ThemeResource answers, without following
// it; whatever else the service answers is an error, so the door stays
// closed.
func TestResourceVersion_ReadsTheRedirect(t *testing.T) {
	p := newPKI(t)
	const file = "login/rasputin/css/tokens.css"
	for _, tc := range []struct {
		name     string
		status   int
		location string
		want     string
		kind     error
	}{
		{"absolute redirect", http.StatusTemporaryRedirect, "https://127.0.0.1:8443/resources/wvpes/" + file, "wvpes", nil},
		{"relative redirect", http.StatusTemporaryRedirect, "/resources/ab12z/" + file, "ab12z", nil},
		{"the probe is the version", http.StatusOK, "", resourceVersionProbe, nil},
		{"another file", http.StatusTemporaryRedirect, "/resources/wvpes/login/rasputin/css/other.css", "", ErrProtocol},
		{"two segments", http.StatusTemporaryRedirect, "/resources/a/b/" + file, "", ErrProtocol},
		{"not under resources", http.StatusTemporaryRedirect, "/realms/rasputin/" + file, "", ErrProtocol},
		{"no location", http.StatusTemporaryRedirect, "", "", ErrProtocol},
		{"not found", http.StatusNotFound, "", "", ErrProtocol},
		{"server error", http.StatusServiceUnavailable, "", "", ErrUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked string
			srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
				asked = r.URL.Path
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(tc.status)
			}, nil)
			c, _ := newClient(t, p, srv.URL)
			v, err := c.ResourceVersion(context.Background(), file)
			if asked != "/resources/"+resourceVersionProbe+"/"+file {
				t.Errorf("asked for %q", asked)
			}
			if srv.requests() != 1 {
				t.Errorf("%d requests, want 1: a redirect is never followed", srv.requests())
			}
			if tc.kind == nil {
				if err != nil || v != tc.want {
					t.Fatalf("got %q, %v; want %q", v, err, tc.want)
				}
				return
			}
			if !errors.Is(err, tc.kind) || v != "" {
				t.Fatalf("got %q, %v; want kind %v", v, err, tc.kind)
			}
		})
	}
}

func TestResourceVersion_RefusesABadFile(t *testing.T) {
	p := newPKI(t)
	srv := newServer(t, p, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }, nil)
	c, _ := newClient(t, p, srv.URL)
	for _, f := range []string{"", "/login/x.css", "login/../admin/x.js"} {
		if _, err := c.ResourceVersion(context.Background(), f); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("file %q: %v, want ErrInvalidValue", f, err)
		}
	}
	if srv.requests() != 0 {
		t.Errorf("%d requests sent for refused files", srv.requests())
	}
}
