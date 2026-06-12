package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// SetUIDir tells the server to serve the built web UI (a Next.js static
// export — see ui/next.config.mjs) from dir as the mux fallback. Empty (the
// default) leaves the api headless: every non-API path 404s, which is the
// right shape for dev runs where `next dev` owns the UI on :3000.
func (s *Server) SetUIDir(dir string) { s.uiDir = dir }

// uiHandler resolves request paths against a Next.js static export:
//
//	/                  → index.html
//	/login             → login.html        (export emits <route>.html)
//	/firewall/rules    → firewall/rules.html
//	/_next/static/...  → exact file        (content-hashed, cached immutable)
//	anything else      → 404.html with status 404
//
// All files are public by design — the bundle contains no secrets and the
// data behind it only flows through the session-gated /api routes.
type uiHandler struct {
	fsys fs.FS
}

func (h uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Static files are read-only; the handler is registered method-less
	// (see Handler), so gate here.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p := path.Clean("/" + r.URL.Path)[1:] // "" for the root
	if p == "" {
		p = "index.html"
	}
	if !fs.ValidPath(p) {
		http.NotFound(w, r)
		return
	}

	name, ok := h.resolve(p)
	if !ok {
		// Unknown path → the export's 404 page, with an honest status so
		// curl/scripts aren't fooled. Plain 404 if even that is missing.
		if body, err := fs.ReadFile(h.fsys, "404.html"); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
		return
	}

	// _next/static files carry a content hash in the name — cache forever.
	// Everything else (route .html, RSC .txt payloads) must revalidate so a
	// new image's UI shows up on the next reload, not after a cache purge.
	if strings.HasPrefix(name, "_next/static/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFileFS(w, r, h.fsys, name)
}

// resolve maps a cleaned, slash-free request path to a file in the export.
func (h uiHandler) resolve(p string) (string, bool) {
	if st, err := fs.Stat(h.fsys, p); err == nil && !st.IsDir() {
		return p, true
	}
	if html := p + ".html"; fileExists(h.fsys, html) {
		return html, true
	}
	// Directory-style fallback, in case a future export uses
	// trailingSlash: true ("login/index.html" instead of "login.html").
	if idx := p + "/index.html"; fileExists(h.fsys, idx) {
		return idx, true
	}
	return "", false
}

func fileExists(fsys fs.FS, name string) bool {
	st, err := fs.Stat(fsys, name)
	return err == nil && !st.IsDir()
}
