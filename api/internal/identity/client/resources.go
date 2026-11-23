package idclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// resourceVersionProbe is the resource version segment the probe asks
// under. It is a well-formed tag (five of [0-9a-z]), so the service answers
// it rather than refusing it as malformed.
const resourceVersionProbe = "00000"

// ResourceVersion reads the resource version segment the running identity
// service serves its theme files under, /resources/<v>/
// (geekdojo/geekdojo-brain#985). Keycloak 26.8.2 sets <v> at start to the id
// of its migration table's newest row (QuarkusJpaConnectionProviderFactory),
// a random tag written when the database is created and again when an upgrade
// migrates it (MigrationModelAdapter.setStoredVersion), so it is per cluster
// and changes on an upgrade. The service exposes it on its theme endpoint:
// asked for file under any other well-formed version, it answers a redirect
// to the same file under <v> (ThemeResource.getResource), which this reads
// without following.
//
// file is the path below the version, such as login/rasputin/css/tokens.css:
// a file the theme serves with no content hash. A redirect whose Location is
// not that file under one segment is ErrProtocol; so is any status but a
// redirect, or 200, which means the probe's segment is the version. The
// segment is returned as the service wrote it; the caller checks its shape.
func (c *Client) ResourceVersion(ctx context.Context, file string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	path := "/resources/" + resourceVersionProbe + "/" + file
	v, e := c.resourceVersion(ctx, path, file)
	if e != nil {
		return "", c.failed(ctx, e)
	}
	return v, nil
}

func (c *Client) resourceVersion(ctx context.Context, path, file string) (string, *Error) {
	fail := func(kind, cause error, status int) *Error {
		return &Error{Op: "resource-version", Path: path, Status: status, Kind: kind, Err: cause}
	}
	if file == "" || strings.HasPrefix(file, "/") || strings.Contains(file, "..") {
		return "", fail(ErrInvalidValue, errors.New("the probe file is not a plain relative path"), 0)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, http.NoBody)
	if err != nil {
		return "", fail(ErrInvalidValue, errors.New("the request could not be built"), 0)
	}
	// The transport, not the client: a redirect is the answer, never
	// followed.
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		kind, cause := classifyTransport(ctx, err)
		return "", fail(kind, cause, 0)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	switch {
	case resp.StatusCode == http.StatusOK:
		return resourceVersionProbe, nil
	case resp.StatusCode >= 500:
		return "", fail(ErrUnreachable, errors.New("the theme endpoint answered a server error"), resp.StatusCode)
	case resp.StatusCode < 300 || resp.StatusCode > 399:
		return "", fail(ErrProtocol, errors.New("the theme endpoint did not redirect the probe"), resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", fail(ErrProtocol, errors.New("the redirect's Location does not parse"), resp.StatusCode)
	}
	rest, ok := strings.CutPrefix(loc.EscapedPath(), "/resources/")
	v, tail, cut := strings.Cut(rest, "/")
	if !ok || !cut || v == "" || tail != file {
		return "", fail(ErrProtocol, errors.New("the redirect is not the probe file under one version"), resp.StatusCode)
	}
	return v, nil
}
