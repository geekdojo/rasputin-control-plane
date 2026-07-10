package api

import (
	_ "embed"
	"log"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
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
	arch := r.URL.Query().Get("arch")
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
	version := ""
	for _, n := range cps {
		if n.ImageVersion != "" {
			version = n.ImageVersion
			break
		}
	}
	if version == "" {
		writeError(w, http.StatusServiceUnavailable, "cluster OS version not known yet")
		return
	}
	base := s.releaseDownloadBase
	if base == "" {
		base = "https://github.com"
	}
	osComp, _ := releases.ComponentByID("os")
	desc, err := releases.PublicNodeImage(r.Context(), http.DefaultClient, base, osComp.Repo, version, compatible)
	if err != nil {
		log.Printf("cluster node-image (os %s, %s): %v", version, compatible, err)
		writeError(w, http.StatusBadGateway, "couldn't resolve the node image for this cluster's version + architecture")
		return
	}
	writeJSON(w, http.StatusOK, desc)
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
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = s.releaseChannel
	}
	info, err := s.releaseSource.LatestFor(r.Context(), comp, channel)
	if err != nil {
		log.Printf("cluster firewall-image (%s): %v", channel, err)
		writeError(w, http.StatusBadGateway, "couldn't resolve the latest firewall image")
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
	writeJSON(w, http.StatusOK, releases.NodeImageDescriptor{
		Version:      info.Version,
		Architecture: art.Architecture,
		URL:          url,
		SHA256:       art.SHA256,
		Image:        art.Image,
	})
}
