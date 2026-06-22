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
// public download URL + checksum. Unauthenticated and secret-free — the flasher
// script (run from a laptop, no session) fetches it, and it carries only the
// version, the public image URL, and its sha256.
func (s *Server) handleClusterNodeImage(w http.ResponseWriter, r *http.Request) {
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
	desc, err := releases.PublicNodeImage(r.Context(), http.DefaultClient, base, s.releaseRepo, version, "rasputin-n100")
	if err != nil {
		log.Printf("cluster node-image (os-%s): %v", version, err)
		writeError(w, http.StatusBadGateway, "couldn't resolve the node image for this cluster's version")
		return
	}
	writeJSON(w, http.StatusOK, desc)
}
