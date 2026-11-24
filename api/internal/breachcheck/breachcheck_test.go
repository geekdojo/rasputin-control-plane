package breachcheck

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// rangeFixtureRelease is the range answer testdata/range-5BAA6.txt was
// captured from, and when: the pin of .github/third-party-capabilities.tsv
// T173. Re-recording the fixture bumps it, which fails gatereg until the row
// is re-verified.
const rangeFixtureRelease = "api.pwnedpasswords.com/range:2026-11-24"

const (
	// listedSHA1 is SHA-1("password"), the public test vector, and listedTail
	// its part after the 5BAA6 prefix, listed in the fixture with a count
	// above 0.
	listedSHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	listedTail = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	// unlisted shares the 5BAA6 prefix (SHA-1 5BAA634AE1D0...) and is absent
	// from the fixture.
	unlisted = "rasputin-unlisted-249637"
)

// seen is one request the range stub received.
type seen struct {
	method, path, query string
	header              http.Header
	body                string
}

// rangeStub is a TLS stand-in for the range API.
type rangeStub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []seen
}

func newRangeStub(t *testing.T, h http.HandlerFunc) *rangeStub {
	t.Helper()
	s := &rangeStub{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/range-5BAA6.txt")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serve(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }
}

func (s *rangeStub) checker(t *testing.T, timeout time.Duration) *Checker {
	t.Helper()
	base, err := url.Parse(s.srv.URL + "/range")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Client: s.srv.Client(), Base: base, CallTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func listed(t *testing.T, c *Checker, pw string) (bool, error) {
	t.Helper()
	v := secret.New([]byte(pw))
	defer v.Destroy()
	return c.Listed(context.Background(), v)
}

// TC-1145-24: "password" is listed, by one GET to /range/5BAA6 with
// Add-Padding and a User-Agent, no body, and nothing past the prefix.
func TestListed_ListedAndRequestShape(t *testing.T) {
	s := newRangeStub(t, serve(fixture(t)))
	got, err := listed(t, s.checker(t, 5*time.Second), "password")
	if err != nil || !got {
		t.Fatalf("Listed(password) = %v, %v; want true", got, err)
	}
	if len(s.reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(s.reqs))
	}
	r := s.reqs[0]
	if r.method != http.MethodGet || r.path != "/range/5BAA6" || r.query != "" || r.body != "" {
		t.Errorf("request %s %s?%s body %q; want GET /range/5BAA6 with no query or body", r.method, r.path, r.query, r.body)
	}
	if r.header.Get("Add-Padding") != "true" || r.header.Get("User-Agent") == "" {
		t.Errorf("headers %v; want Add-Padding: true and a User-Agent", r.header)
	}
	whole := r.method + r.path + r.query + r.body
	for k, vs := range r.header {
		whole += k + strings.Join(vs, ",")
	}
	for _, leak := range []string{listedTail, listedSHA1} {
		if strings.Contains(strings.ToUpper(whole), leak) {
			t.Errorf("the request holds %s", leak)
		}
	}
}

// TC-1145-25: an absent suffix under the same prefix is not listed, and the
// target suffix as a padding entry (count 0) is not listed.
func TestListed_NotListedAndPadding(t *testing.T) {
	s := newRangeStub(t, serve(fixture(t)))
	if got, err := listed(t, s.checker(t, 5*time.Second), unlisted); err != nil || got {
		t.Errorf("Listed(unlisted) = %v, %v; want false", got, err)
	}
	padded := newRangeStub(t, serve([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"+listedTail+":0\r\n")))
	if got, err := listed(t, padded.checker(t, 5*time.Second), "password"); err != nil || got {
		t.Errorf("Listed(password) as padding = %v, %v; want false", got, err)
	}
	lower := newRangeStub(t, serve([]byte(strings.ToLower(listedTail)+":3\n")))
	if got, err := listed(t, lower.checker(t, 5*time.Second), "password"); err != nil || !got {
		t.Errorf("Listed(password) against a lower-case LF line = %v, %v; want true", got, err)
	}
}

// noLeak fails if an error's text holds the prefix, a suffix, a body line
// or the request URL.
func noLeak(t *testing.T, what string, err error, stub *rangeStub, body string) {
	t.Helper()
	text := err.Error()
	bad := []string{"5BAA6", "5baa6", listedTail, strings.ToLower(listedTail), "/range", "pwnedpasswords"}
	if stub != nil {
		bad = append(bad, stub.srv.URL)
	}
	for _, l := range strings.Split(body, "\n") {
		if l = strings.TrimSpace(l); len(l) > 3 {
			bad = append(bad, l)
		}
	}
	for _, b := range bad {
		if strings.Contains(text, b) {
			t.Errorf("%s: the error %q holds %q", what, text, b)
		}
	}
}

// TC-1145-26: every unreadable answer is ErrUnexpectedAnswer and no verdict.
func TestListed_UnexpectedAnswers(t *testing.T) {
	for _, code := range []int{503, 429, 404} {
		s := newRangeStub(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, listedTail+":9\r\n")
		})
		got, err := listed(t, s.checker(t, 5*time.Second), "password")
		if got || !errors.Is(err, ErrUnexpectedAnswer) {
			t.Errorf("status %d: %v, %v; want ErrUnexpectedAnswer", code, got, err)
			continue
		}
		if !strings.Contains(err.Error(), "(status "+strconv.Itoa(code)+")") {
			t.Errorf("status %d: the error %q does not hold the status", code, err)
		}
		noLeak(t, "status", err, s, listedTail+":9")
	}
	big := strings.Repeat("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n", (maxBody/39)+2)
	for what, body := range map[string]string{
		"no colon":           listedTail + "\r\n",
		"a short suffix":     "1E4C9B93F3F0682250B6CF8331B7EE68FD:5\r\n",
		"a long suffix":      listedTail + "0:5\r\n",
		"a non-hex suffix":   "1E4C9B93F3F0682250B6CF8331B7EE68FDZ:5\r\n",
		"a non-number count": listedTail + ":many\r\n",
		"a negative count":   listedTail + ":-1\r\n",
		"over 1 MiB":         big,
	} {
		s := newRangeStub(t, serve([]byte(body)))
		got, err := listed(t, s.checker(t, 5*time.Second), "password")
		if got || !errors.Is(err, ErrUnexpectedAnswer) {
			t.Errorf("%s: %v, %v; want ErrUnexpectedAnswer", what, got, err)
			continue
		}
		if what != "over 1 MiB" {
			noLeak(t, what, err, s, body)
		}
	}
}

// TC-1145-27: a server that never answers is bounded by CallTimeout; a
// closed one is a dial error; neither error names the URL or the prefix.
func TestListed_TransportFailures(t *testing.T) {
	release := make(chan struct{})
	hang := newRangeStub(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	start := time.Now()
	got, err := listed(t, hang.checker(t, 100*time.Millisecond), "password")
	if got || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a server that never answers: %v, %v; want context.DeadlineExceeded", got, err)
	} else {
		noLeak(t, "timeout", err, hang, "")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("the timeout took %s, want under 2s", el)
	}

	closed := newRangeStub(t, serve(nil))
	c := closed.checker(t, 5*time.Second)
	closed.srv.Close()
	got, err = listed(t, c, "password")
	var op *net.OpError
	if got || !errors.As(err, &op) || op.Op != "dial" {
		t.Errorf("a closed server: %v, %v; want a dial *net.OpError", got, err)
	} else {
		noLeak(t, "dial", err, closed, "")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		t.Errorf("the error still wraps the *url.Error: %v", err)
	}
}

// TC-1145-28: New refuses each bad config and accepts a good one.
func TestNew_Refuses(t *testing.T) {
	good, _ := url.Parse("https://api.pwnedpasswords.com/range")
	plain, _ := url.Parse("http://api.pwnedpasswords.com/range")
	for what, cfg := range map[string]Config{
		"nil Client":   {Base: good, CallTimeout: time.Second},
		"nil Base":     {Client: &http.Client{}, CallTimeout: time.Second},
		"http Base":    {Client: &http.Client{}, Base: plain, CallTimeout: time.Second},
		"zero timeout": {Client: &http.Client{}, Base: good},
	} {
		if c, err := New(cfg); err == nil || c != nil {
			t.Errorf("New with %s = %v, %v; want a refusal", what, c, err)
		}
	}
	if c, err := New(Config{Client: &http.Client{}, Base: good, CallTimeout: time.Second}); err != nil || c == nil {
		t.Errorf("New with a good config = %v, %v", c, err)
	}
	if !strings.HasPrefix(rangeFixtureRelease, "api.pwnedpasswords.com/range:") {
		t.Errorf("rangeFixtureRelease %q is not the range API's pin", rangeFixtureRelease)
	}
}
