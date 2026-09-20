package releases

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// friendlyFetchError turns a release-fetch failure into a short, vendor-neutral,
// user-facing message for the control-plane UI. The raw error is logged by the
// caller for diagnostics — it can name internal hosts, the upstream resolver IP,
// and Go's net internals (e.g. `Get "https://api.github.com/...": dial tcp:
// lookup api.github.com on 127.0.0.53:53: ... i/o timeout`), none of which an
// operator clicking "Check for updates" should see. This collapses every such
// failure into one of a few actionable messages.
func friendlyFetchError(err error) string {
	if err == nil {
		return ""
	}

	// Signature problems, before the transport classes below. These are not
	// network faults and the network advice would send an operator to look at
	// the wrong thing entirely (geekdojo/geekdojo-brain#527).
	switch {
	case errors.Is(err, ErrManifestSignerExpired):
		return "This release's signing certificate has expired, so its manifest can no longer be verified. " +
			"Update to a current release — a current release is signed by a current certificate."
	case errors.Is(err, ErrManifestUnsigned):
		return "The published release has no signature on its manifest, so it was refused. " +
			"Nothing was installed."
	case errors.Is(err, ErrManifestVersionMismatch):
		return "The published release's signed manifest does not match the release it was published under, so it was refused."
	case errors.Is(err, ErrNoVerifier):
		return "This control plane has no publisher trust root, so it cannot verify a release. " +
			"On an appliance, re-flash; on a dev box, run scripts/pki-init.sh."
	}

	// Non-200 from the release host: classify by status code.
	var he *httpError
	if errors.As(err, &he) {
		switch {
		case he.status == 403 || he.status == 429:
			return "The update server is rate-limiting requests right now. Wait a few minutes and try again."
		case he.status >= 500:
			return "The update server is temporarily unavailable. Try again shortly."
		case he.status == 404:
			return "No update information was found for this release channel."
		default:
			return "The update server returned an unexpected response. Try again shortly."
		}
	}

	// Timeouts: request deadline, or a slow/unreachable network. url.Error,
	// net.OpError, and net.DNSError all satisfy net.Error and bubble Timeout()
	// up, so a DNS i/o timeout lands here too.
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "Timed out reaching the update server. Check this node's internet connection and try again."
	}

	// DNS failure, no route, connection refused/reset, network down — the node
	// has no working path to the internet.
	var dnsErr *net.DNSError
	var opErr *net.OpError
	if errors.As(err, &dnsErr) ||
		errors.As(err, &opErr) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) {
		return "Couldn't reach the update server. Check this node's internet connection and try again."
	}

	// Unknown failure: stay generic rather than leak internals.
	return "Couldn't check for updates. Try again shortly."
}
