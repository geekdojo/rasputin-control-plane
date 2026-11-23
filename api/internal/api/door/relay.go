package door

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
)

// clientCertHeaders are the client-certificate headers a proxy in front of
// Keycloak could set; a client's copy never reaches upstream.
var clientCertHeaders = []string{
	"X-Client-Cert", "X-SSL-Client-Cert", "X-Forwarded-Client-Cert", "Ssl-Client-Cert", "Client-Cert", "Client-Cert-Chain",
}

// newProxy is the relay: the door's own connection pool, the forwarded
// headers written from the door table, the cookie and header rules on the
// way back, and the not-ready page for an upstream that does not answer.
func (h *Handler) newProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:        h.rewrite,
		Transport:      h.cfg.Transport,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.upstreamFailed,
		// Copy errors after the answer started go through the injected
		// logger (F-985-14).
		ErrorLog: slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
	}
}

// rewrite builds the outbound request: every client Forwarded,
// X-Forwarded-* and client-certificate header deleted, then Host, Proto,
// Port and For written from the door table and the peer, the door's host as
// Host, and the cookies filtered.
func (h *Handler) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(h.cfg.Upstream)
	out := pr.Out.Header
	for k := range out {
		if k == "Forwarded" || strings.HasPrefix(k, "X-Forwarded-") {
			delete(out, k)
		}
	}
	for _, k := range clientCertHeaders {
		out.Del(k)
	}
	out.Set("X-Forwarded-Host", h.cfg.Door.Host)
	out.Set("X-Forwarded-Proto", "https")
	out.Set("X-Forwarded-Port", strconv.Itoa(doors.Port))
	if ap, err := netip.ParseAddrPort(pr.In.RemoteAddr); err == nil {
		out.Set("X-Forwarded-For", ap.Addr().Unmap().String())
	}
	pr.Out.Host = h.cfg.Door.Host
	inboundCookies(h.cfg.Kind, out)
}

// errVersionMoved is a theme file the identity service redirected: it does
// that only when the version asked is not its own (ThemeResource at 26.8.2),
// so the version the door holds is stale.
var errVersionMoved = errors.New("the identity service redirected a theme file: its resource version has changed")

// modifyResponse applies the response headers and the outbound cookie rule.
// A redirected theme file is never relayed: it is the fact that the
// identity service's resource version changed, so the version is read again
// and the request answers the 404 door page.
func (h *Handler) modifyResponse(resp *http.Response) error {
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 && strings.HasPrefix(stateOf(resp.Request).pattern, "/resources/") {
		h.cfg.Version.Stale()
		return errVersionMoved
	}
	h.pol.setHeaders(resp.Header, h.pol.relayed(h.cfg.Version.Current()))
	outboundCookies(h.cfg.Kind, resp.Header)
	return nil
}

// upstreamFailed answers a request the identity service did not answer with
// the not-ready page as a 502, and records the error's class only: never its
// text, which names the URL.
func (h *Handler) upstreamFailed(w http.ResponseWriter, r *http.Request, err error) {
	st := stateOf(r)
	if errors.Is(err, errVersionMoved) {
		h.notFound(w, r, st)
		return
	}
	st.errorClass = errorClass(err)
	h.render(w, http.StatusBadGateway, h.notReadyPage(r, st))
}

// errorClass is a transport error's class.
func errorClass(err error) string {
	var opErr *net.OpError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &certErr):
		return "tls"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "connect"
	case errors.As(err, &opErr) && opErr.Op == "remote error":
		return "tls"
	}
	return "transport"
}

// relay forwards an admitted request. A route that can store events is
// recorded open on the drain's signal while it is relayed, so a drain pass
// holds its mark behind the request's events until they are committed (the
// identity service commits them before its answer completes). Once the
// answer has completed (or failed), a held credential post's slot is
// reported answered, the request is closed and the drain is marked dirty, in
// that order, so the pass that releases the slot starts after the answer.
func (h *Handler) relay(w http.ResponseWriter, r *http.Request, rt Route, d policy.Decision) {
	end := func() {}
	if rt.Kind.EventProducing() {
		end = h.cfg.Dirty.Begin()
	}
	defer func() {
		if d.Held {
			h.cfg.Throttle.Answered(d.HeldKey)
		}
		end()
		if rt.Kind.EventProducing() {
			h.cfg.Dirty.MarkDirty()
		}
	}()
	h.proxy.ServeHTTP(w, r)
}
