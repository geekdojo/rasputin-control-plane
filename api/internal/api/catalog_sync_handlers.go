package api

import (
	"net/http"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
)

// SetCatalogSync wires the fetched-catalog machinery. Optional: an api built
// without it serves the embedded catalog and reports itself as such, which is
// exactly what an airgapped cluster does at runtime.
func (s *Server) SetCatalogSync(store *catalogsync.Store, poller *catalogsync.Poller) {
	s.catalogStore = store
	s.catalogPoller = poller
}

// catalogStatus is what the UI needs to answer "which catalog am I on, and why".
type catalogStatus struct {
	Version int    `json:"version"`
	Source  string `json:"source"` // "fetched" | "embedded"
	Tiles   int    `json:"tiles"`
	// Checked is null until a poll has COMPLETED. Null and "checked, found
	// nothing" are different states and the UI must not render them the same:
	// a cluster that has never reached the internet would otherwise look
	// identical to one that is up to date. That is #149's failure mode, where
	// the updates panel read "nothing available" when it had simply never
	// looked.
	Checked *time.Time `json:"lastChecked"`
	Error   string     `json:"lastError,omitempty"`
	Note    string     `json:"note,omitempty"`
}

// GET /api/catalog/_status — provenance of the catalog currently in effect.
//
// The path segment is deliberately "_status" and not "status". Tile ids are
// DNS-1123 labels, "status" is a perfectly legal one, and GET
// /api/catalog/{id} already exists — so a literal /api/catalog/status route
// would silently shadow a tile somebody could publish. An underscore is not a
// legal DNS-1123 character, which makes the two namespaces disjoint by
// construction rather than by anyone remembering.
func (s *Server) handleCatalogStatus(w http.ResponseWriter, r *http.Request) {
	if s.catalogStore == nil {
		writeJSON(w, http.StatusOK, catalogStatus{
			Version: 0,
			Source:  "embedded",
			Tiles:   len(s.catalog.All()),
			Note:    "catalog fetching is not configured; serving the catalog embedded in this build",
		})
		return
	}

	version, fromFetch, note := s.catalogStore.State()
	out := catalogStatus{
		Version: version,
		Source:  "embedded",
		Tiles:   len(s.catalogStore.Current().Tiles),
		Note:    note,
	}
	if fromFetch {
		out.Source = "fetched"
	}
	if s.catalogPoller != nil {
		if at, err := s.catalogPoller.LastChecked(); !at.IsZero() {
			t := at
			out.Checked = &t
			if err != nil {
				out.Error = err.Error()
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/catalog/_refresh — ask for a poll now.
//
// Returns 202: the poll runs on the poller's goroutine and may take as long as
// a download. Doing it inline would let a slow or hostile mirror hold an api
// request open, and would make a double-click two concurrent fetches.
func (s *Server) handleCatalogRefresh(w http.ResponseWriter, r *http.Request) {
	if s.catalogPoller == nil {
		writeError(w, http.StatusServiceUnavailable, "catalog fetching is not configured on this cluster")
		return
	}
	s.catalogPoller.Refresh()
	w.WriteHeader(http.StatusAccepted)
}
