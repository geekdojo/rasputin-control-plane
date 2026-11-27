// Package repaircode is `rasputin-api repair-code` (geekdojo/geekdojo-brain#321):
// root on the control plane makes a one-time repair code.
//
// The command refuses unless its output is a terminal, since the code is
// printed once and must not land in a file or a pipe (LOG-SECRETS). It draws
// 100 random bits, shown as 20 RFC 4648 base-32 characters, sends the api
// only their SHA-256 over TLS 1.3 on the root-only repair-code socket,
// verifying the api by chain to the identity CA, and prints the code once
// with the addresses it is typed at.
package repaircode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
)

// ServerName is the name the socket's leaf carries. .invalid is reserved, so
// it resolves nowhere.
const ServerName = "repair-code.rasputin.invalid"

// The exit codes.
const (
	exitOK      = 0
	exitFailed  = 1
	exitRefused = 2
)

// The sentences the command prints on stderr.
const (
	sentenceNotTerminal = "This prints a one-time repair code, so run it in a terminal (ssh -t gives it one)."
	sentenceNoAPI       = "The control plane's api isn't taking repair codes. Is rasputin-api running?"
	sentenceUnverified  = "The control plane's api couldn't be verified, so no code was made."
	sentenceRefused     = "The control plane's api refused the repair code, so no code was made."
	sentenceNoRandom    = "No random bits could be read, so no code was made."
)

// codeChars is the code's length: 20 base-32 characters carry 100 bits.
const codeChars = 20

// randBytes is what is drawn: 13 bytes give 21 base-32 characters, of which
// the first 20 are kept.
const randBytes = 13

// callBound bounds the one call to the socket. It decides nothing.
const callBound = 30 * time.Second

// Deps are the command's collaborators.
type Deps struct {
	Stdout, Stderr io.Writer
	// IsTerminal reports whether a file descriptor is a terminal. Stdout's
	// descriptor is read from its Fd method; a Stdout without one is never
	// a terminal.
	IsTerminal func(fd uintptr) bool
	Rand       io.Reader
	// Dial connects to the repair-code socket.
	Dial func(ctx context.Context) (net.Conn, error)
	// CAPEM is the identity CA's certificate; empty when it couldn't be
	// read.
	CAPEM []byte
}

// Run makes one code and returns the exit code.
func Run(ctx context.Context, d Deps) int {
	if f, ok := d.Stdout.(interface{ Fd() uintptr }); !ok || !d.IsTerminal(f.Fd()) {
		fmt.Fprintln(d.Stderr, sentenceNotTerminal)
		return exitRefused
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(d.CAPEM) {
		fmt.Fprintln(d.Stderr, sentenceUnverified)
		return exitFailed
	}
	raw := make([]byte, randBytes)
	defer clear(raw)
	if _, err := io.ReadFull(d.Rand, raw); err != nil {
		fmt.Fprintln(d.Stderr, sentenceNoRandom)
		return exitFailed
	}
	enc := []byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	defer clear(enc)
	code := enc[:codeChars]
	hash := breakglass.Hash(code)

	urls, sentence := send(ctx, d, pool, hash)
	if sentence != "" {
		fmt.Fprintln(d.Stderr, sentence)
		return exitFailed
	}
	shown := make([]byte, 0, codeChars+3)
	for i := 0; i < codeChars; i += 5 {
		if i > 0 {
			shown = append(shown, '-')
		}
		shown = append(shown, code[i:i+5]...)
	}
	defer clear(shown)
	var b strings.Builder
	b.WriteString("Repair code, shown once:\n\n    ")
	b.Write(shown)
	b.WriteString("\n\nOn a device on the same network, open one of these and type the code:\n")
	for _, u := range urls {
		b.WriteString("    " + u + "\n")
	}
	b.WriteString("\nThe code opens one repair session. It stops working once it is used, when a newer code is made, " +
		"when an administrator signs in normally, or when the control plane's api restarts.\n")
	fmt.Fprint(d.Stdout, b.String())
	return exitOK
}

// send posts hash to the socket and returns the URLs it answered, or the
// sentence to print.
func send(ctx context.Context, d Deps, pool *x509.CertPool, hash [32]byte) ([]string, string) {
	ctx, cancel := context.WithTimeout(ctx, callBound)
	defer cancel()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return d.Dial(ctx) },
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    pool,
			ServerName: ServerName,
		},
		ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()
	body, err := json.Marshal(breakglass.CodeRequest{SHA256: hex.EncodeToString(hash[:])})
	if err != nil {
		return nil, sentenceRefused
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+ServerName+breakglass.CodePath, strings.NewReader(string(body)))
	if err != nil {
		return nil, sentenceRefused
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		var cve *tls.CertificateVerificationError
		if errors.As(err, &cve) {
			return nil, sentenceUnverified
		}
		return nil, sentenceNoAPI
	}
	defer func() { _ = resp.Body.Close() }() // read below; a failed close drops only the connection
	if resp.StatusCode != http.StatusOK {
		return nil, sentenceRefused
	}
	var out breakglass.CodeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&out); err != nil {
		return nil, sentenceRefused
	}
	return out.URLs, ""
}
