package api

import "net/http"

// handleObsStatus returns a snapshot of the obs stack — whether it's
// enabled (RASPUTIN_OBS_ENABLED at startup), whether VictoriaMetrics
// reports healthy, and when the metrics fan-out last succeeded / failed.
// Always 200; "obs disabled" is conveyed via Snapshot.Enabled=false, not
// an HTTP error, so the UI's polling loop stays simple.
//
// The status struct itself is nil-safe — if obs wasn't wired into the
// Server, this returns Enabled=false with zero values rather than 500.
func (s *Server) handleObsStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.obs.Snapshot(r.Context())
	writeJSON(w, http.StatusOK, snap)
}
