package signin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Console is what ConsoleSignIn needs: the console's origin and the
// transport that reaches it and its sign-in page.
type Console struct {
	// Origin is the console's origin, https://<cid>.local.
	Origin string
	// Transport carries every request; it holds the TLS trust and maps the
	// cluster's names to the test's addresses.
	Transport http.RoundTripper
	// Logger receives one DEBUG record per page. Nothing secret is logged.
	Logger *slog.Logger
}

// ConsoleRefusedError is the console sending the sign-in back to its
// launcher with a reason (/login?signin=<Reason>).
type ConsoleRefusedError struct{ Reason string }

func (e *ConsoleRefusedError) Error() string {
	return fmt.Sprintf("signin: the console refused the sign-in: signin=%s", e.Reason)
}

// ConsoleSignIn signs user in to the console through its launcher's route,
// the way a browser does (geekdojo/geekdojo-brain#989): GET
// <origin>/api/auth/signin, the redirect to the home door's sign-in page,
// the sign-in form posted, the door's return to the console's callback, and
// the console's redirect to its launcher. It returns the cookie jar, which
// then holds the console session, and the page ids it passed. The password
// leaves its secret.Value only in the form body.
func ConsoleSignIn(ctx context.Context, c Console, user string, password secret.Value) (*cookiejar.Jar, []string, error) {
	switch {
	case c.Origin == "" || c.Transport == nil || c.Logger == nil:
		return nil, nil, errors.New("signin: Console needs Origin, Transport and Logger")
	}
	origin, err := url.Parse(c.Origin)
	if err != nil {
		return nil, nil, fmt.Errorf("signin: the console's origin: %w", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("signin: cookie jar: %w", err)
	}
	f := &flow{
		c: &Client{cfg: Config{Logger: c.Logger}},
		http: &http.Client{Transport: c.Transport, Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	defer f.http.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.Origin, "/")+"/api/auth/signin", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("signin: the console's sign-in request: %w", err)
	}
	for range maxHops {
		resp, err := f.http.Do(req)
		if err != nil {
			return nil, f.pages, fmt.Errorf("signin: %s %s: %w", req.Method, redact(req.URL), err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close() // the body is read; a failed close only drops the connection
		if err != nil {
			return nil, f.pages, fmt.Errorf("signin: read %s: %w", redact(req.URL), err)
		}
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc, err := resp.Location()
			if err != nil {
				return nil, f.pages, fmt.Errorf("signin: a %d from %s with no usable Location: %w", resp.StatusCode, redact(req.URL), err)
			}
			if loc.Host == origin.Host && loc.Path == "/login" {
				if reason := loc.Query().Get("signin"); reason != "" {
					return nil, f.pages, &ConsoleRefusedError{Reason: reason}
				}
				return jar, f.pages, nil
			}
			if req, err = http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil); err != nil {
				return nil, f.pages, fmt.Errorf("signin: follow the redirect: %w", err)
			}
		case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
			page, err := ParsePage(body)
			if err != nil {
				return nil, f.pages, err
			}
			f.pages = append(f.pages, page.ID)
			f.themes = append(f.themes, page.Theme)
			c.Logger.Debug("sign-in page", "page_id", page.ID, "status", resp.StatusCode)
			if req, err = f.next(ctx, resp.Request.URL, page, user, password); err != nil {
				return nil, f.pages, err
			}
		default:
			return nil, f.pages, fmt.Errorf("signin: %s answered %d", redact(req.URL), resp.StatusCode)
		}
	}
	return nil, f.pages, fmt.Errorf("signin: the console sign-in did not return to the launcher within %d hops", maxHops)
}
