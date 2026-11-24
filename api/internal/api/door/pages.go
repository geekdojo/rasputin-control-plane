package door

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The door's own pages: one template, framed like the login theme and
// styled from the files the door serves at /_signin/, so they render while
// the identity service is down (signin-origin.md §5.1). They carry
// script-src 'none'.

//go:embed pages.html.tmpl
var pagesTemplate string

var pageTmpl = template.Must(template.New("door").Parse(pagesTemplate))

// signinPrefix is the door's reserved path, never forwarded upstream.
const signinPrefix = "/_signin/"

// The page kinds.
const (
	pageNotReady = "not-ready"
	pageRefusal  = "refusal"
	pageInfo     = "info"
	pageWarning  = "warning"
)

// The not-ready sentence (signin-origin.md §5.1), with the install name, and
// its fallback when the name is empty or unreadable (F-985-15).
const (
	notReadyStart    = "Sign-in isn't available right now. Try again in a moment. "
	notReadyNamed    = "If it stays like this, tell whoever runs %s."
	notReadyFallback = "If it stays like this, tell whoever runs this cluster."
)

// page is one door page's data.
type page struct {
	Kind          string
	Title         string
	Heading       string
	Sentence      string
	InstallName   string
	Name          string
	TryAgain      string
	Back          string
	BackText      string
	CorrelationID string
	Error         bool
	// The warning page's (breach.go): its hint, the choose-another link, and
	// the Keep form's action, marker and echoed fields.
	Hint      string
	Choose    string
	Keep      string
	KeepField string
	Fields    []hiddenField
}

// hiddenField is one posted field the Keep form echoes. Its value is a
// plain string, never a secret.Value, which html/template would render as
// its redaction marker.
type hiddenField struct{ Name, Value string }

// render writes p with status, under the door page's headers.
func (h *Handler) render(w http.ResponseWriter, status int, p page) {
	var b bytes.Buffer
	if err := pageTmpl.Execute(&b, p); err != nil {
		// The template is fixed and parsed at init; its data is strings. A
		// failure here is a programming error, answered with the sentence
		// alone rather than a half-written page.
		h.setPageHeaders(w.Header())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(p.Sentence + "\n"))
		return
	}
	h.setPageHeaders(w.Header())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

// asset is one file the door serves at /_signin/.
type asset struct {
	body  []byte
	ctype string
}

// assetTypes are the content types of the files under /_signin/.
var assetTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".woff2": "font/woff2",
	".svg":   "image/svg+xml",
	".txt":   "text/plain; charset=utf-8",
}

// requiredAssets are the files every door page links.
var requiredAssets = []string{"css/tokens.css", "css/components.css", "css/signin.css"}

// loadAssets reads the built theme's login/resources css/ and img/ trees
// from fsys into memory. It refuses a tree missing a file the pages link, or
// a file of a type the door does not serve.
func loadAssets(fsys fs.FS) (map[string]asset, error) {
	out := map[string]asset{}
	for _, dir := range []string{"css", "img"} {
		err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ctype, ok := assetTypes[path.Ext(p)]
			if !ok {
				return fmt.Errorf("door: %s is not a file type the door serves", p)
			}
			b, err := fs.ReadFile(fsys, p)
			if err != nil {
				return err
			}
			out[p] = asset{body: b, ctype: ctype}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("door: the sign-in files: %w", err)
		}
	}
	for _, f := range requiredAssets {
		if _, ok := out[f]; !ok {
			return nil, errors.New("door: the sign-in files hold no " + f)
		}
	}
	return out, nil
}

// serveAsset answers GET /_signin/<file> from memory, or the 404 page.
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, st *reqState) {
	a, ok := h.assets[strings.TrimPrefix(r.URL.Path, signinPrefix)]
	if !ok {
		h.notFound(w, r, st)
		return
	}
	h.setPageHeaders(w.Header())
	w.Header().Set("Content-Type", a.ctype)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(a.body)
}

// notReadySentence is the not-ready page's sentence with the install name,
// or its fallback.
func (h *Handler) notReadySentence(r *http.Request) (string, string) {
	name, err := h.cfg.InstallName(r.Context())
	name = strings.TrimSpace(name)
	if err != nil || name == "" {
		return notReadyStart + notReadyFallback, ""
	}
	return notReadyStart + fmt.Sprintf(notReadyNamed, name), name
}

// notReadyPage is the page people read while sign-in is not available.
func (h *Handler) notReadyPage(r *http.Request, st *reqState) page {
	sentence, name := h.notReadySentence(r)
	return page{
		Kind: pageNotReady, Title: "Sign-in isn't available", Heading: "SIGN-IN ISN'T AVAILABLE",
		Sentence: sentence, InstallName: name, TryAgain: r.URL.RequestURI(), CorrelationID: st.id, Error: true,
	}
}

// refusalPage is a refusal with its sentence.
func (h *Handler) refusalPage(sentence string, st *reqState) page {
	return page{Kind: pageRefusal, Title: "Sign-in refused", Heading: "THIS CAN'T CONTINUE", Sentence: sentence,
		CorrelationID: st.id, Error: true}
}

// InfoPage renders an info page: Identity 4.10's reset result and 4.4's
// landing page use it.
func (h *Handler) InfoPage(w http.ResponseWriter, heading, sentence, correlationID string) {
	h.render(w, http.StatusOK, page{Kind: pageInfo, Title: heading, Heading: strings.ToUpper(heading),
		Sentence: sentence, CorrelationID: correlationID})
}

// RefusalPage renders a refusal that names a refused value and links back
// to a form: Identity 4.8's registration refusal uses it.
func (h *Handler) RefusalPage(w http.ResponseWriter, status int, sentence, name, back, correlationID string) {
	p := page{Kind: pageRefusal, Title: "Sign-in refused", Heading: "THIS CAN'T CONTINUE", Sentence: sentence,
		Name: name, CorrelationID: correlationID, Error: true}
	if back != "" {
		p.Back, p.BackText = back, "Go back"
	}
	h.render(w, status, p)
}
