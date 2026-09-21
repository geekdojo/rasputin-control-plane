package api

import (
	_ "embed"
	"errors"
	"log"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

//go:embed flash.sh
var flashScript []byte

// handleGetFlashScript serves the one-command node flasher. Intentionally
// unauthenticated and secret-free: the operator runs it on a laptop via
// `curl … | sudo … bash`, which carries no session cookie. The only secret —
// the enrollment seed — is supplied by the operator through the
// RASPUTIN_SEED_B64 env var in the one-liner the Add-node wizard shows; this
// endpoint never sees or returns it.
func (s *Server) handleGetFlashScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(flashScript)
}

// handleClusterNodeImage returns the flashable OS image a NEW node should use
// to match this cluster: the control plane's own OS version resolved to a
// public download URL + checksum, for the requested CPU architecture
// (?arch=amd64|arm64, default amd64). Unauthenticated and secret-free — the
// flasher script (run from a laptop, no session) fetches it, and it carries
// only the version, the public image URL, its sha256, and the arch.
func (s *Server) handleClusterNodeImage(w http.ResponseWriter, r *http.Request) {
	// The amd64 default lives HERE, not inside ArchCompatible, because the two
	// callers ask different questions with the same function. The flasher asks
	// "which image should I write to a blank disk", where a default is a
	// legitimate convenience chosen by a human at a keyboard who can see the
	// arch label the script prints back. The fleet plan asks "which image does
	// THIS node take", where the same default is a guess about a fact — the
	// #67 defect. Keeping it at this layer preserves the endpoint's documented
	// behaviour and stops it leaking into the plan.
	arch := r.URL.Query().Get("arch")
	if arch == "" {
		arch = "amd64"
	}
	compatible, ok := releases.ArchCompatible(arch)
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported arch (expected amd64 or arm64)")
		return
	}
	cps, err := s.inv.ListByRole(r.Context(), proto.RoleControlPlane)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	version := clusterOSVersion(cps)
	if version == "" {
		writeError(w, http.StatusServiceUnavailable, "cluster OS version not known yet")
		return
	}
	// The version is inventory data reported by a node, and it becomes a path
	// segment of the download URL: refuse anything that is not a plain release
	// tag rather than resolve it.
	if !releases.ValidReleaseVersion(version) {
		log.Printf("cluster node-image: controlplane OS version %q is not a valid release version", version)
		writeError(w, http.StatusServiceUnavailable, "cluster OS version is not a valid release version")
		return
	}
	base := s.releaseDownloadBase
	if base == "" {
		base = "https://github.com"
	}
	osComp, _ := releases.ComponentByID("os")
	desc, err := releases.PublicNodeImage(r.Context(), http.DefaultClient, s.updaterVerifier, base, osComp, version, compatible)
	if err != nil {
		// %q on the error, not %v: as of geekdojo/geekdojo-brain#527 this error
		// can carry text derived from a REMOTE document (a release manifest's
		// own version, a signing leaf's common name). Each of those is already
		// escaped where the error is built, but an escape one level away is the
		// kind of reasoning that rots — the next error added to that chain
		// would silently undo it. Escaping here makes it true at the line that
		// writes the log. This is still the #145 class (version and compatible
		// are interpolated with %s); it is simply not widened by this change.
		log.Printf("cluster node-image (os %s, %s): %q", version, compatible, err.Error())
		status, msg := nodeImageError(err, version)
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, desc)
}

// nodeImageError turns a manifest-resolution failure into the status and the
// sentence an operator should read.
//
// The signature checks introduced with geekdojo/geekdojo-brain#527 can fail for
// reasons that are not "the release is broken", and the generic 502 that used
// to cover everything sent the operator to the wrong place for each of them.
// Three get their own answer:
//
//   - An EXPIRED signing certificate (dec 24, geekdojo/geekdojo-brain#576).
//     Every release is signed by a leaf with a finite life, so a cluster that
//     stays on one version long enough eventually cannot fetch the first-flash
//     image for its OWN version any more. Nothing is wrong with the release and
//     nothing is wrong with the cluster: it is simply too old, and the fix is to
//     update it. Bryce decided the requirement rather than work around it, so
//     the message has to SAY that instead of reporting a signature failure and
//     leaving an operator hunting for an attack.
//   - NO TRUST ROOT on this control plane. An installation fault, not a bad
//     artifact — 503, naming the fix.
//   - Everything else stays a 502.
func nodeImageError(err error, version string) (int, string) {
	switch {
	case errors.Is(err, releases.ErrManifestSignerExpired):
		return http.StatusConflict, "this cluster is on " + version +
			", and the certificate that signed that release has expired — so its image can no longer be verified. " +
			"Update the cluster before adding a node; a current release is signed by a current certificate. " +
			"Nothing is wrong with the node you are adding."
	case errors.Is(err, releases.ErrNoVerifier), errors.Is(err, updater.ErrTrustUnavailable):
		return http.StatusServiceUnavailable, "this control plane has no publisher trust root, so it cannot verify the release manifest " +
			"for this cluster's version. On an appliance, re-flash; on a dev box, run scripts/pki-init.sh."
	default:
		return http.StatusBadGateway, "couldn't resolve the node image for this cluster's version + architecture"
	}
}

// clusterOSVersion picks the OS version a NEW node should be flashed with, from
// the controlplane node(s). A CONFIRMED version wins over an unconfirmed one
// (ADR-0005 Decision 4): an unconfirmed value is one an update outcome told us
// not to trust, and flashing a new node to it would seed the cluster's newest
// member from its least reliable fact.
//
// An unconfirmed value is still used when it is all there is, deliberately.
// Refusing would mean a cluster whose controlplane update failed to verify
// cannot add nodes at all — turning a stale-version problem into an
// onboarding outage, which is far worse for the operator than flashing a node
// with a version that may be one release off and is fixed by an ordinary
// update. Logged so the choice is visible in the journal rather than silent.
func clusterOSVersion(cps []*proto.Node) string {
	fallback := ""
	for _, n := range cps {
		if n.ImageVersion == "" {
			continue
		}
		if n.ImageVersionConfirmedAt != nil {
			return n.ImageVersion
		}
		if fallback == "" {
			fallback = n.ImageVersion
		}
	}
	if fallback != "" {
		log.Printf("cluster node-image: no controlplane has a CONFIRMED image version; falling back to the unconfirmed %q", fallback)
	}
	return fallback
}

// handleClusterFirewallImage returns the flashable firewall image a new
// firewall node should be imaged with — the LATEST firewall release on the
// cluster's update channel resolved to a public download URL + checksum. Unlike
// the OS node image (handleClusterNodeImage), the firewall is a separate,
// x86-only image on its own release cadence, so it isn't tied to the cluster's
// OS version; we take the newest published build. Unauthenticated and
// secret-free — it carries only the version, the public image URL, its sha256,
// and the arch (always amd64). The enrollment seed is delivered separately,
// out of band, over SSH; this endpoint never sees it.
//
// ?channel= overrides the configured channel and must name a known one
// (releases.ParseChannel); anything else is a 400. This endpoint is
// unauthenticated and the channel reaches a log line, so an unvalidated value
// would let any caller forge log lines with an encoded newline
// (geekdojo/geekdojo-brain#145).
func (s *Server) handleClusterFirewallImage(w http.ResponseWriter, r *http.Request) {
	if s.releaseSource == nil {
		writeError(w, http.StatusServiceUnavailable, "update channel not configured on this control plane")
		return
	}
	comp, ok := releases.ComponentByID("fw")
	if !ok {
		writeError(w, http.StatusInternalServerError, "firewall component not registered")
		return
	}
	channel := s.releaseChannel
	if q := r.URL.Query().Get("channel"); q != "" {
		known, ok := releases.ParseChannel(q)
		if !ok {
			writeError(w, http.StatusBadRequest, "unknown release channel (want "+releases.ChannelStable+" or "+releases.ChannelDev+")")
			return
		}
		channel = known
	}
	info, err := s.releaseSource.LatestFor(r.Context(), comp, channel)
	if err != nil {
		// %q on the error, for the reason given in handleClusterNodeImage.
		log.Printf("cluster firewall-image (%s): %q", channel, err.Error())
		// Before giving up: this control plane may simply have no route. The
		// no-DHCP bootstrap address carries no gateway by design (rasputin-os
		// #53), and that is the path where the operator most needs a firewall
		// image -- the firewall is what would restore internet. Fall back to
		// the manifest rasputin-os baked in at build time, verified here
		// exactly as an online one would be (geekdojo/geekdojo-brain#595).
		bakedBase := s.releaseDownloadBase
		if bakedBase == "" {
			bakedBase = "https://github.com"
		}
		if d, berr := releases.BakedFirewallImage(s.updaterVerifier, bakedBase, comp); berr == nil {
			log.Printf("cluster firewall-image (%s): serving the BAKED manifest for %s (this control plane could not reach the release source)", channel, d.Version)
			writeJSON(w, http.StatusOK, d)
			return
		} else if !errors.Is(berr, releases.ErrNoBakedManifest) {
			// A baked manifest that is present and BAD is worth saying out
			// loud; an absent one is just an older or dev image.
			log.Printf("cluster firewall-image (%s): baked manifest unusable: %q", channel, berr.Error())
		}
		status, msg := nodeImageError(err, "the latest firewall release")
		if status == http.StatusBadGateway {
			msg = "couldn't resolve the latest firewall image"
		}
		writeError(w, status, msg)
		return
	}
	if info == nil {
		writeError(w, http.StatusNotFound, "no firewall release on channel "+channel)
		return
	}
	// The firewall's full-disk initial-flash artifact is the `image`
	// (*-ab.img.gz); its checksum lives in `sha256` (distinct from the OS, whose
	// `sha256` covers the RAUC bundle and whose image sha is `imageSha256`).
	art, ok := info.Artifact(comp.Compatible)
	if !ok || art.Image == "" || art.SHA256 == "" {
		writeError(w, http.StatusBadGateway, "firewall release "+info.Version+" has no flashable image")
		return
	}
	url, ok := info.AssetURL(art.Image)
	if !ok {
		writeError(w, http.StatusBadGateway, "firewall release "+info.Version+" missing asset "+art.Image)
		return
	}
	desc := releases.NodeImageDescriptor{
		Version:      info.Version,
		Architecture: art.Architecture,
		URL:          url,
		SHA256:       art.SHA256,
		Image:        art.Image,
	}
	// The firewall descriptor carries no manifest+signature yet, because no
	// firewall release publishes one (releases.Components: the fw entry's
	// SignedManifestFrom is empty). Once geekdojo/geekdojo-brain#526 ships and
	// that floor is set, LatestFor verifies the manifest and this is where the
	// verified bytes would travel on to flash.sh, exactly as the OS path does.
	desc.Signer = info.Signer
	writeJSON(w, http.StatusOK, desc)
}
