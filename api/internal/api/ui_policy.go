package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// pageHostRE is the Host a page policy will name as its script origin: a DNS
// name or IPv4 address made of letters, digits, dots and hyphens, starting
// and ending with a letter or digit, with an optional numeric port. Anything
// else (an IPv6 literal, which CSP's host grammar cannot express, or a value
// carrying spaces, quotes or semicolons) gets no script source at all.
var pageHostRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$`)

// pagePolicy is the Content-Security-Policy for one console page (a .html file
// of the static export), served to request r. Its script-src is exactly:
//
//   - <scheme>://<host>/_next/: the page's own origin, under the path the
//     export serves every script file from. Never 'self', which on this
//     origin would also admit Grafana's scripts under /observability/
//     (C31/C32). The scheme is https over TLS and http on the plain-HTTP
//     trust page;
//   - 'wasm-unsafe-eval': the backup-key passphrase KDF is Argon2id from
//     hash-wasm (ui/lib/passphrase-kdf.ts), which compiles WebAssembly. It
//     permits WebAssembly compilation only, not eval();
//   - one 'sha256-…' per inline <script> (one without a src attribute) in
//     page, hashed from the bytes the api is about to serve, so the hashes
//     are always the served build's own.
//
// Every other directive is the baseline's. A Host that is not acceptable, or
// a page that cannot be tokenised, gets the baseline's script-src 'none':
// the page's scripts are blocked, never allowed. Only a non-browser client
// sends such a Host, so this is not logged.
func pagePolicy(r *http.Request, page []byte) string {
	if !pageHostRE.MatchString(r.Host) {
		return contentSecurityPolicy
	}
	hashes, err := inlineScriptHashes(page)
	if err != nil {
		return contentSecurityPolicy
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	src := scheme + "://" + r.Host + "/_next/ 'wasm-unsafe-eval'"
	for _, h := range hashes {
		src += " '" + h + "'"
	}
	return cspWithScriptSrc(src)
}

// inlineScriptHashes returns the CSP hash source ("sha256-<base64>") of each
// distinct inline <script> in page, in document order. The tokenizer hands
// back a script's raw text with CR and CRLF normalised to LF, which is the
// text a browser hashes.
func inlineScriptHashes(page []byte) ([]string, error) {
	z := html.NewTokenizer(bytes.NewReader(page))
	var out []string
	seen := map[string]bool{}
	inScript := false
	var text []byte
	for {
		switch z.Next() {
		case html.ErrorToken:
			if err := z.Err(); !errors.Is(err, io.EOF) {
				return nil, err
			}
			return out, nil
		case html.StartTagToken:
			name, hasAttr := z.TagName()
			if atom.Lookup(name) != atom.Script {
				continue
			}
			inScript = !scriptHasSrc(z, hasAttr)
			text = text[:0]
		case html.TextToken:
			if inScript {
				text = append(text, z.Text()...)
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if inScript && atom.Lookup(name) == atom.Script {
				sum := sha256.Sum256(text)
				h := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
				if !seen[h] {
					seen[h] = true
					out = append(out, h)
				}
				inScript = false
			}
		}
	}
}

// scriptHasSrc reports whether the start tag the tokenizer is on carries a
// src attribute.
func scriptHasSrc(z *html.Tokenizer, hasAttr bool) bool {
	for hasAttr {
		var key []byte
		key, _, hasAttr = z.TagAttr()
		if strings.EqualFold(string(key), "src") {
			return true
		}
	}
	return false
}
