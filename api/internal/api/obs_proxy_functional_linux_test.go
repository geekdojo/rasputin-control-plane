//go:build linux

// Functional test: the UI still renders Grafana after geekdojo-brain#453.
//
// The browser never talks to Grafana. It talks to the api's /observability/
// reverse proxy (obs_proxy.go), which now reaches Grafana over a unix socket
// instead of a TCP port. This test puts the REAL proxy handler in front of the
// REAL pinned Grafana image, brought up by the api's own supervisor in socket
// mode, and drives it the way the UI's iframe does:
//
//	(a) pages render — the app shell HTML, the static assets it references
//	    under serve_from_sub_path, and a dashboard page;
//	(b) the Grafana API calls the UI makes succeed — frontend settings,
//	    search, the dashboard model, and a panel query through the
//	    VictoriaMetrics datasource;
//	(c) Grafana Live's WebSocket upgrade works through the proxy: the
//	    httputil.ReverseProxy upgrade path over a unix-dialing transport,
//	    carried as far as a real Live (centrifuge) connect reply.
//
// Opt-in: RASPUTIN_GRAFANA_FUNCTIONAL must be set; "required" turns skips into
// failures (what CI sets). Linux + docker only — see obs's
// grafana_functional_linux_test.go for why it is opt-in.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

const proxyFuncProject = "rasputin-obs-proxyfunc"

func proxyFuncRequireDocker(t *testing.T) {
	t.Helper()
	mode := os.Getenv("RASPUTIN_GRAFANA_FUNCTIONAL")
	if mode == "" {
		t.Skip("set RASPUTIN_GRAFANA_FUNCTIONAL=1 to run (needs docker)")
	}
	fail := func(format string, args ...any) {
		t.Helper()
		if mode == "required" {
			t.Fatalf("RASPUTIN_GRAFANA_FUNCTIONAL=required but "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		fail("docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		fail("docker daemon unreachable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

func proxyFuncComposeDown() {
	_ = exec.Command("docker", "compose", "-p", proxyFuncProject, "down", "-v",
		"--remove-orphans").Run()
}

func TestObsProxyGrafanaUI_OverSocket(t *testing.T) {
	proxyFuncRequireDocker(t)

	// Short: the socket path must stay under the ~104-byte sun_path limit.
	stateDir, err := os.MkdirTemp("/tmp", "rgp")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	proxyFuncComposeDown()
	t.Cleanup(proxyFuncComposeDown)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	on, off := true, false
	sup, err := obs.NewDockerComposeSupervisor(obs.DockerComposeSupervisorConfig{
		StateDir:         stateDir,
		ProjectName:      proxyFuncProject,
		VMListenAddr:     "127.0.0.1:19316",
		UseGrafanaSocket: &on,
		EnableLoki:       &off,
		EnableVMAlert:    &off,
		EnableCadvisor:   &off,
		HealthTimeout:    150 * time.Second,
		PullTimeout:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if sup.GrafanaSocketPath() == "" || sup.GrafanaTransport() == nil {
		t.Fatal("Grafana is not on a socket — this test would prove nothing")
	}

	// The real handler, behind a stand-in for the session middleware: in
	// production RequireSession puts the passkey user in the context.
	sink, err := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	srv := &Server{obs: obs.NewStatus(sup, sink, nil)}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(auth.WithUser(r.Context(), &auth.User{Name: "alice"}))
		srv.handleObservabilityProxy(w, r)
	}))
	defer front.Close()

	client := front.Client()
	client.Timeout = 30 * time.Second
	get := func(t *testing.T, path string) (int, http.Header, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+path, nil)
		// A browser on the operator's session may carry anything; the
		// proxy must overwrite it.
		req.Header.Set("X-Webauth-User", "admin")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// The provisioned dashboard can be invisible for a fixed 60s on a fresh
	// DB (measured; see obs's starterDashboardDeadline), so find its uid by
	// polling for up to twice that.
	var dashUID string
	{
		deadline := time.Now().Add(120 * time.Second)
		for dashUID == "" {
			code, _, body := get(t, "/observability/api/search?type=dash-db")
			// Only an empty 200 is the provisioning window worth waiting
			// out; anything else means the proxy cannot reach Grafana.
			if code != http.StatusOK {
				t.Fatalf("search through the proxy = %d %s", code, body)
			}
			var hits []struct {
				UID   string `json:"uid"`
				Title string `json:"title"`
			}
			if json.Unmarshal([]byte(body), &hits) == nil {
				for _, h := range hits {
					if h.Title == "Cluster Overview" {
						dashUID = h.UID
					}
				}
			}
			if dashUID != "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("starter dashboard not searchable through the proxy after 120s: %d %s", code, body)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	t.Run("a: pages and static assets render", func(t *testing.T) {
		code, hdr, html := get(t, "/observability/")
		if code != http.StatusOK {
			t.Fatalf("app shell = %d", code)
		}
		if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("app shell content-type = %q", ct)
		}
		// serve_from_sub_path: the shell sets <base href="/observability/">
		// and references its assets relative to it (public/build/…), so a
		// browser fetches /observability/public/…. Resolve them the same way
		// and load every one through the proxy.
		base := regexp.MustCompile(`<base href="([^"]+)"`).FindStringSubmatch(html)
		if base == nil || base[1] != "/observability/" {
			t.Fatalf("shell <base href> = %v, want /observability/", base)
		}
		refs := regexp.MustCompile(`(?:src|href)="((?:/observability/)?public/(?:build|img)/[^"]+)"`).
			FindAllStringSubmatch(html, -1)
		seen := map[string]bool{}
		kinds := map[string]int{}
		for _, m := range refs {
			a := m[1]
			if !strings.HasPrefix(a, "/") {
				a = base[1] + a
			}
			if seen[a] {
				continue
			}
			seen[a] = true
			code, hdr, body := get(t, a)
			if code != http.StatusOK || len(body) == 0 {
				t.Errorf("asset %s = %d (%d bytes)", a, code, len(body))
				continue
			}
			ct := hdr.Get("Content-Type")
			switch {
			case strings.Contains(ct, "javascript"):
				kinds["js"]++
			case strings.Contains(ct, "css"):
				kinds["css"]++
			case strings.HasPrefix(ct, "image/"):
				kinds["img"]++
			default:
				t.Errorf("asset %s content-type = %q", a, ct)
			}
		}
		// Grafana 11.5.1's shell references both (measured: 8 js, 2 css).
		if kinds["css"] == 0 || kinds["js"] == 0 {
			t.Fatalf("shell assets not all loaded through the proxy: %v (refs: %v)", kinds, refs)
		}
		t.Logf("loaded %d distinct static assets through the proxy: %v", len(seen), kinds)

		// A dashboard page — what the UI's iframe actually points at.
		code, hdr, _ = get(t, "/observability/d/"+dashUID)
		if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
			t.Errorf("dashboard page = %d %q", code, hdr.Get("Content-Type"))
		}
		// allow_embedding: the iframe must not be refused by the browser.
		if xfo := hdr.Get("X-Frame-Options"); strings.EqualFold(xfo, "deny") {
			t.Errorf("X-Frame-Options = %q; the UI's iframe embed would be blocked", xfo)
		}
	})

	var vmUID string
	t.Run("b: the API calls the UI makes succeed", func(t *testing.T) {
		code, _, body := get(t, "/observability/api/frontend/settings")
		if code != http.StatusOK {
			t.Fatalf("frontend settings = %d", code)
		}
		var fs struct {
			AppURL      string `json:"appUrl"`
			AppSubURL   string `json:"appSubUrl"`
			Datasources map[string]struct {
				UID string `json:"uid"`
			} `json:"datasources"`
		}
		if err := json.Unmarshal([]byte(body), &fs); err != nil {
			t.Fatalf("frontend settings json: %v", err)
		}
		if fs.AppSubURL != "/observability" {
			t.Errorf("appSubUrl = %q, want /observability", fs.AppSubURL)
		}
		// Regression guard: with protocol = socket, a %(protocol)s root_url
		// became socket://… in every URL Grafana generates.
		if !strings.HasPrefix(fs.AppURL, "http://") {
			t.Errorf("appUrl = %q, want http://… (not socket://)", fs.AppURL)
		}
		vmUID = fs.Datasources["VictoriaMetrics"].UID
		if vmUID == "" {
			t.Fatalf("VictoriaMetrics datasource not in frontend settings: %.500s", body)
		}

		// Identity: the proxy's header wins over the client's `admin`.
		code, _, body = get(t, "/observability/api/user")
		if code != http.StatusOK || !strings.Contains(body, `"login":"alice"`) {
			t.Errorf("/api/user = %d %s; want the session user alice", code, body)
		}

		code, _, body = get(t, "/observability/api/dashboards/uid/"+dashUID)
		if code != http.StatusOK || !strings.Contains(body, "Cluster Overview") {
			t.Errorf("dashboard model = %d %.300s", code, body)
		}

		// A panel query, exactly as a dashboard panel issues it.
		// vector(1) returns a sample without depending on any series having
		// been scraped yet.
		q := fmt.Sprintf(`{"queries":[{"refId":"A","datasource":{"uid":%q,"type":"prometheus"},`+
			`"expr":"vector(1)","instant":true}],"from":"now-5m","to":"now"}`, vmUID)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			front.URL+"/observability/api/ds/query", strings.NewReader(q))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", front.URL)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("ds/query: %v", err)
		}
		qb, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ds/query = %d %.500s", resp.StatusCode, qb)
		}
		if !strings.Contains(string(qb), `"A"`) || !strings.Contains(string(qb), `"values"`) {
			t.Errorf("ds/query returned no frame for A: %.500s", qb)
		}
	})

	t.Run("c: Grafana Live websocket upgrades through the proxy", func(t *testing.T) {
		wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/observability/api/live/ws"
		dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
		defer dcancel()
		// Same-origin, as the browser sends it: Grafana Live refuses a
		// cross-origin upgrade.
		conn, resp, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Origin": []string{front.URL}},
		})
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Fatalf("websocket dial through the proxy: %v (HTTP %d)", err, status)
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
		}
		// Carry it past the handshake: a Live (centrifuge JSON) connect
		// command must get its reply back through the hijacked socket.
		if err := conn.Write(dctx, websocket.MessageText, []byte(`{"id":1,"connect":{}}`)); err != nil {
			t.Fatalf("write connect: %v", err)
		}
		_, msg, err := conn.Read(dctx)
		if err != nil {
			t.Fatalf("read connect reply: %v", err)
		}
		if !strings.Contains(string(msg), `"id":1`) || !strings.Contains(string(msg), `"connect"`) {
			t.Fatalf("unexpected Live reply: %s", msg)
		}
		t.Logf("Live connect reply through the proxy: %.200s", msg)
	})
}
