package api

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
)

// The loopback-publish and one-web-port rules on a custom app's declared web
// port (geekdojo/geekdojo-brain#1091), through POST /api/apps and
// PUT /api/apps/{id}/compose on a real SQLite fixture.

const (
	// everyInterface8080 publishes 8080 on every interface.
	everyInterface8080 = "services:\n  web:\n    image: me/web:2\n    ports: [\"8080:80\"]\n"
	// loopback8080 publishes 8080 on loopback only.
	loopback8080 = "services:\n  web:\n    image: me/web:2\n    ports: [\"127.0.0.1:8080:80\"]\n"
	// notYAML is a YAML syntax error.
	notYAML = "services: ["

	msgEveryInterface8080 = `Web port 8080 is published on every interface, not loopback: write it as "127.0.0.1:8080:<container>" so only the node proxy reaches it.`
	msgNotPublished9090   = `Web port 9090 is not published: add "127.0.0.1:9090:<container>" to the service that serves it.`
)

// refusedRecords is every "api: request refused" record the server wrote.
func refusedRecords(f *apiFixture) []slog.Record {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()
	var out []slog.Record
	for _, r := range f.logs.recs {
		if r.Message == "api: request refused" {
			out = append(out, r)
		}
	}
	return out
}

// refusalAttrs is the attributes of the one refusal record under the body's
// correlation id.
func refusalAttrs(t *testing.T, f *apiFixture, body []byte) map[string]string {
	t.Helper()
	recs := f.logs.withAttr("correlation_id", decodeCoded(t, body).CorrelationID)
	if len(recs) != 1 {
		t.Fatalf("want one record for %s, got %d", body, len(recs))
	}
	out := map[string]string{}
	recs[0].Attrs(func(a slog.Attr) bool { out[a.Key] = a.Value.String(); return true })
	return out
}

// assertNothingLeaks fails if any of the record's values, or the body,
// carries one of the given texts.
func assertNothingLeaks(t *testing.T, attrs map[string]string, body []byte, texts ...string) {
	t.Helper()
	for _, x := range texts {
		for k, v := range attrs {
			if strings.Contains(v, x) {
				t.Errorf("record attr %s=%q carries %q", k, v, x)
			}
		}
		if strings.Contains(string(body), x) && x != "8080" {
			t.Errorf("body %s carries %q", body, x)
		}
	}
}

// TC-1091-12: create with a port the compose publishes on every interface is
// a coded 400 with the rule's text, one WARN record, and no row.
func TestCreateApp_WebPortNotLoopbackRefused(t *testing.T) {
	f := newWebPortFixture(t)
	w := f.do(t, http.MethodPost, "/api/apps", createRequest("bad", everyInterface8080, "8080"), f.cookie)
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortNotLoopback, msgEveryInterface8080, "POST /api/apps")
	attrs := refusalAttrs(t, f.apiFixture, w.Body.Bytes())
	if attrs["cause"] != "bind" {
		t.Errorf("cause = %q, want bind", attrs["cause"])
	}
	assertNothingLeaks(t, attrs, w.Body.Bytes(), "services", "me/web", "8080")
	if a, _ := f.appsStore.GetByName(f.ctx, "bad"); a != nil {
		t.Errorf("a row was written: %+v", a)
	}
}

// TC-1091-13: create with a port and a compose that is not YAML is refused
// with the unreadable text, and neither the decoder's error nor the compose
// reaches the body or the log.
func TestCreateApp_WebPortComposeUnreadable(t *testing.T) {
	f := newWebPortFixture(t)
	w := f.do(t, http.MethodPost, "/api/apps", createRequest("bad", notYAML, "8080"), f.cookie)
	const want = "The Compose file could not be read, so the web port it publishes cannot be checked."
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortComposeUnreadable, want, "POST /api/apps")
	attrs := refusalAttrs(t, f.apiFixture, w.Body.Bytes())
	if attrs["cause"] != "yaml" {
		t.Errorf("cause = %q, want yaml", attrs["cause"])
	}
	assertNothingLeaks(t, attrs, w.Body.Bytes(), "yaml:", "did not find", "line 1", notYAML)
	if a, _ := f.appsStore.GetByName(f.ctx, "bad"); a != nil {
		t.Errorf("a row was written: %+v", a)
	}
}

// TC-1091-14: with no port, create does not read the compose, as before.
func TestCreateApp_NoWebPortIsNotChecked(t *testing.T) {
	f := newWebPortFixture(t)
	for name, compose := range map[string]string{"every-interface": everyInterface8080, "not-yaml": notYAML} {
		w := f.do(t, http.MethodPost, "/api/apps", createRequest(name, compose, ""), f.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: want 201, got %d %s", name, w.Code, w.Body.String())
		}
		if p := f.row(t, decodeBody[apps.App](t, w.Body.String()).ID).PublishedPort; p != 0 {
			t.Errorf("%s: port %d, want 0", name, p)
		}
	}
	if recs := refusedRecords(f.apiFixture); len(recs) != 0 {
		t.Errorf("%d refusal records, want none", len(recs))
	}
}

// TC-1091-15: create with a port published on loopback stores it.
func TestCreateApp_WebPortOnLoopback(t *testing.T) {
	f := newWebPortFixture(t)
	w := f.do(t, http.MethodPost, "/api/apps", createRequest("good", loopback8080, "8080"), f.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d %s", w.Code, w.Body.String())
	}
	if p := f.row(t, decodeBody[apps.App](t, w.Body.String()).ID).PublishedPort; p != 8080 {
		t.Errorf("port %d, want 8080", p)
	}
}

// TC-1091-16: an edit with a new compose and a port is refused when the
// compose does not publish the port on loopback, and nothing is started,
// held or written.
func TestPutCompose_WebPortNotLoopbackRefused(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 0)
	before := f.row(t, webPortAppID)
	w := f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose",
		`{"composeYaml":`+jsonString(everyInterface8080)+`,"webPort":8080}`, f.cookie)
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortNotLoopback, msgEveryInterface8080, "PUT /api/apps/{id}/compose", "app_id")
	attrs := refusalAttrs(t, f.apiFixture, w.Body.Bytes())
	if attrs["app_id"] != webPortAppID || attrs["cause"] != "bind" {
		t.Errorf("record app_id=%q cause=%q, want %s and bind", attrs["app_id"], attrs["cause"], webPortAppID)
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("%d edits held", n)
	}
	if after := f.row(t, webPortAppID); after.ComposeSHA256 != before.ComposeSHA256 || after.PublishedPort != 0 {
		t.Errorf("row changed: compose same %v, port %d", after.ComposeSHA256 == before.ComposeSHA256, after.PublishedPort)
	}
}

// TC-1091-17: a compose-only edit is checked against the stored port, which
// the app keeps.
func TestPutCompose_ComposeOnlyEditChecksTheStoredPort(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 8080)
	w := f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose", composeYAMLBody(t, everyInterface8080), f.cookie)
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortNotLoopback, msgEveryInterface8080, "PUT /api/apps/{id}/compose", "app_id")

	f.put(t, webPortAppID, composeYAMLBody(t, loopback8080), http.StatusAccepted)
	if row := f.row(t, webPortAppID); row.ComposeYAML != loopback8080 || row.PublishedPort != 8080 {
		t.Errorf("row compose new=%v port=%d, want true and 8080", row.ComposeYAML == loopback8080, row.PublishedPort)
	}
}

// TC-1091-18: an app with no port, as every custom app from an earlier
// release is, is not checked on a compose-only edit.
func TestPutCompose_NoPortIsNotChecked(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 0)
	f.put(t, webPortAppID, composeYAMLBody(t, everyInterface8080), http.StatusAccepted)
	if recs := refusedRecords(f.apiFixture); len(recs) != 0 {
		t.Errorf("%d refusal records, want none", len(recs))
	}
}

// TC-1091-19: a port-only edit checks the installed compose against the new
// port.
func TestPutCompose_PortOnlyEditIsChecked(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, loopback8080, 8080)
	w := f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose",
		`{"composeYaml":`+jsonString(loopback8080)+`,"webPort":9090}`, f.cookie)
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortNotLoopback, msgNotPublished9090, "PUT /api/apps/{id}/compose", "app_id")
	if p := f.row(t, webPortAppID).PublishedPort; p != 8080 {
		t.Errorf("port %d, want 8080", p)
	}

	both := "services:\n  web:\n    image: me/web:2\n    ports: [\"127.0.0.1:8080:80\", \"127.0.0.1:9090:80\"]\n"
	g := newWebPortFixture(t)
	g.seedCustom(t, webPortAppID, both, 8080)
	g.put(t, webPortAppID, `{"composeYaml":`+jsonString(both)+`,"webPort":9090}`, http.StatusAccepted)
	if p := g.row(t, webPortAppID).PublishedPort; p != 9090 {
		t.Errorf("port %d, want 9090", p)
	}
}

// TC-1091-20: the installed compose with no port or the stored one is the
// no-op, and is not re-checked, even when it would fail the rule.
func TestPutCompose_NoOpIsNotRechecked(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, everyInterface8080, 8080)
	for _, extra := range []string{``, `,"webPort":8080`} {
		w := f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose", `{"composeYaml":`+jsonString(everyInterface8080)+extra+`}`, f.cookie)
		if w.Code != http.StatusOK {
			t.Errorf("%q: want 200, got %d %s", extra, w.Code, w.Body.String())
		}
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
}

// TC-1091-21: a catalog app's compose is not the owner's to send, and that
// 409 comes before the web-port rule.
func TestPutCompose_CatalogAppConflictsFirst(t *testing.T) {
	f := newWebPortFixture(t)
	seedUpgradeApp(t, f.apiFixture, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	w := f.do(t, http.MethodPut, "/api/apps/cat/compose", `{"composeYaml":`+jsonString(everyInterface8080)+`,"webPort":9090}`, f.cookie)
	if w.Code != http.StatusConflict || decodeBody[map[string]string](t, w.Body.String())["error"] != apps.ErrEditCatalogApp.Error() {
		t.Errorf("want 409 with ErrEditCatalogApp, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), codeWebPortNotLoopback) {
		t.Errorf("body carries %s: %s", codeWebPortNotLoopback, w.Body.String())
	}
}

// TC-1091-22: a revert restores a compose and port that were installed
// together, so it is not re-checked.
func TestPutCompose_RevertIsNotRechecked(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, everyInterface8080, 8080)
	if err := f.appsStore.EditCompose(f.ctx, webPortAppID, apps.ComposeHash(everyInterface8080), loopback8080, 8080, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	f.put(t, webPortAppID, shaBody(everyInterface8080), http.StatusAccepted)
	if recs := refusedRecords(f.apiFixture); len(recs) != 0 {
		t.Errorf("%d refusal records, want none", len(recs))
	}
}

// TC-1091-23: one web port per app, by the API's shape: an array is not a
// port, on create and on edit.
func TestWebPort_OnePerApp(t *testing.T) {
	f := newWebPortFixture(t)
	w := f.do(t, http.MethodPost, "/api/apps", createRequest("two", loopback8080, "[8080, 8081]"), f.cookie)
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortInvalid, msgWebPortInvalid, "POST /api/apps")
	if c := refusalAttrs(t, f.apiFixture, w.Body.Bytes())["cause"]; c != "type" {
		t.Errorf("create cause = %q, want type", c)
	}
	if a, _ := f.appsStore.GetByName(f.ctx, "two"); a != nil {
		t.Errorf("a row was written: %+v", a)
	}

	f.seedCustom(t, webPortAppID, customOld, 8080)
	w = f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose",
		`{"composeYaml":`+jsonString(loopback8080)+`,"webPort":[8080, 8081]}`, f.cookie)
	assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortInvalid, msgWebPortInvalid, "PUT /api/apps/{id}/compose", "app_id")
	if c := refusalAttrs(t, f.apiFixture, w.Body.Bytes())["cause"]; c != "type" {
		t.Errorf("edit cause = %q, want type", c)
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
}
