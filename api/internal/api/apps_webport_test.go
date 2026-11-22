package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/nats-io/nats.go"
)

// A custom app's web port (geekdojo/geekdojo-brain#1089): "webPort" on
// POST /api/apps and beside "composeYaml" on PUT /api/apps/{id}/compose,
// stored in published_port, and from there carried to the per-app leaf.

const webPortCluster = "c1"

// webPortFixture is upgradeFixture with the deploy, edit and revert sagas
// re-registered over a leaf rotator, and a node on n1 that accepts every
// leaf, so a test can see the route each job delivers.
type webPortFixture struct {
	*apiFixture
	cookie *http.Cookie
	// deploys is every compose the node was told to run.
	deploys <-chan proto.AppDeployCmd
	// leaves is every AppLeafCmd the node received.
	leaves chan proto.AppLeafCmd
}

func newWebPortFixture(t *testing.T) *webPortFixture {
	t.Helper()
	f, cookie, _, deploys := upgradeFixture(t)
	seed, err := appsecret.NewSeed(bytes.Repeat([]byte{7}, appsecret.SeedLen), appsecret.DerivationVersion)
	if err != nil {
		t.Fatal(err)
	}
	src, err := appsecret.NewHKDFSource(seed)
	if err != nil {
		t.Fatal(err)
	}
	// The command main's rotator builds (app_leaf.go buildAppLeafCmd), from
	// the app the saga hands it.
	rotate := func(a *apps.App) (apps.Leaf, bool, func() error, error) {
		tailnet, lan := mesh.AppRouteHosts(webPortCluster, a.Name, a.ExposeLAN)
		return apps.Leaf{Cmd: proto.AppLeafCmd{
			AppID: a.ID, Name: a.Name, CertPEM: []byte("C"), TailnetFQDN: tailnet, LANFQDN: lan,
			UpstreamPort: a.PublishedPort, UpstreamTLS: a.WebTLS,
		}, Key: secret.New([]byte("K"))}, false, nil, nil
	}
	must := func(w jobs.Workflow, err error) jobs.Workflow {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	f.runner.Register(must(apps.DeployWorkflow(f.appsStore, f.inv, f.nc, rotate, src, apps.AppIdentity{})))
	f.runner.Register(must(apps.RevertWorkflow(f.appsStore, f.inv, f.nc, rotate, src, apps.AppIdentity{})))
	f.runner.Register(must(apps.EditWorkflow(f.appsStore, f.inv, f.nc, rotate, f.srv.composeStash, src, testAppSecretDeps(), apps.AppIdentity{})))

	leaves := make(chan proto.AppLeafCmd, 8)
	sub, err := f.nc.Subscribe(proto.AppLeafSubject("n1"), func(m *nats.Msg) {
		var cmd proto.AppLeafCmd
		_ = json.Unmarshal(m.Data, &cmd)
		leaves <- cmd
		ack, _ := json.Marshal(proto.AppLeafAck{OK: true})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return &webPortFixture{apiFixture: f, cookie: cookie, deploys: deploys, leaves: leaves}
}

// seedCustom is a custom app on n1 running compose with port (0 = none), as
// the release before #1089 could leave one.
func (f *webPortFixture) seedCustom(t *testing.T, id, compose string, port int) {
	t.Helper()
	now := time.Now().UTC()
	if err := f.appsStore.Create(f.ctx, &apps.App{
		ID: id, Name: "mine", ComposeYAML: compose, TargetNode: "n1", PublishedPort: port, ExposeLAN: true,
		LastStatus: proto.AppStatusRunning, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *webPortFixture) row(t *testing.T, id string) *apps.App {
	t.Helper()
	a, err := f.appsStore.Get(f.ctx, id)
	if err != nil || a == nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return a
}

// runJob waits for the job a 202 or 201 answered with, and returns it.
func (f *webPortFixture) runJob(t *testing.T, body string) *jobs.Job {
	t.Helper()
	job := decodeBody[jobs.Job](t, body)
	waitForJobs(t, f.runner)
	j, err := f.jobsStore.GetJob(f.ctx, job.ID)
	if err != nil || j == nil {
		t.Fatalf("job %s: %v", job.ID, err)
	}
	// Drain what the node was sent, so a later job's deploy has room.
	for {
		select {
		case <-f.deploys:
			continue
		default:
		}
		break
	}
	return j
}

// put sends PUT /api/apps/{id}/compose and, for a 202, waits for the job.
func (f *webPortFixture) put(t *testing.T, id, body string, want int) *jobs.Job {
	t.Helper()
	w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", body, f.cookie)
	if w.Code != want {
		t.Fatalf("PUT %s: want %d, got %d (%s)", body, want, w.Code, w.Body.String())
	}
	if want != http.StatusAccepted {
		return nil
	}
	j := f.runJob(t, w.Body.String())
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s %s: %s", j.Kind, j.Status, j.Error)
	}
	return j
}

// leaf is the one leaf the node received since the last call, or fails.
func (f *webPortFixture) leaf(t *testing.T) proto.AppLeafCmd {
	t.Helper()
	select {
	case cmd := <-f.leaves:
		return cmd
	default:
		t.Fatal("no leaf was delivered")
		return proto.AppLeafCmd{}
	}
}

// jobLog is every log line the job recorded, one string.
func (f *webPortFixture) jobLog(t *testing.T, jobID string) string {
	t.Helper()
	evs, err := f.jobsStore.ListEvents(f.ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range evs {
		b.Write(e.Data)
		b.WriteByte('\n')
	}
	return b.String()
}

// stepResult is the named step's recorded result.
func (f *webPortFixture) stepResult(t *testing.T, jobID, step string) map[string]any {
	t.Helper()
	steps, err := f.jobsStore.ListSteps(f.ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.Name == step {
			var out map[string]any
			if err := json.Unmarshal(s.Result, &out); err != nil {
				t.Fatalf("step %s result %s: %v", step, s.Result, err)
			}
			return out
		}
	}
	t.Fatalf("job %s has no step %s", jobID, step)
	return nil
}

// assertWebPortRefusal checks a coded refusal: the exact body, and one WARN
// record under its correlation id carrying the route, the code and a fixed
// cause, with no attribute a request could have set.
func assertWebPortRefusal(t *testing.T, f *apiFixture, w interface {
	Result() *http.Response
}, body []byte, code, msg, route string, wantKeys ...string) {
	t.Helper()
	if st := w.Result().StatusCode; st != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", st, body)
	}
	ce := decodeCoded(t, body)
	if ce.Code != code || ce.Error != msg || ce.CorrelationID == "" {
		t.Fatalf("body = %+v, want code %s and %q", ce, code, msg)
	}
	recs := f.logs.withAttr("correlation_id", ce.CorrelationID)
	if len(recs) != 1 || recs[0].Level != slog.LevelWarn || recs[0].Message != "api: request refused" {
		t.Fatalf("records for %s = %v, want one WARN api: request refused", ce.CorrelationID, recs)
	}
	keys := map[string]string{}
	recs[0].Attrs(func(a slog.Attr) bool { keys[a.Key] = a.Value.String(); return true })
	want := append([]string{"correlation_id", "route", "code", "cause"}, wantKeys...)
	if len(keys) != len(want) {
		t.Errorf("record attrs = %v, want exactly %v", keys, want)
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Errorf("record has no %s: %v", k, keys)
		}
	}
	if keys["route"] != route || keys["code"] != code {
		t.Errorf("record route=%q code=%q, want %q and %q", keys["route"], keys["code"], route, code)
	}
	switch keys["cause"] {
	case "type", "range", "compose_absent", "bind", "yaml":
	default:
		t.Errorf("record cause = %q, want a fixed cause", keys["cause"])
	}
}

// createBody is a create request for name with port as "webPort" ("" for
// none). A whole-number port is published on loopback, so the web-port rule
// (geekdojo/geekdojo-brain#1091) passes it.
func createBody(name, port string) string {
	compose := "services: {web: {image: me/web:1}}\n"
	if port != "" && strings.Trim(port, "0123456789") == "" {
		compose = `services: {web: {image: me/web:1, ports: ["127.0.0.1:` + port + `:80"]}}` + "\n"
	}
	return createRequest(name, compose, port)
}

// createRequest is a create request for name with compose and port as
// "webPort" ("" for none).
func createRequest(name, compose, port string) string {
	b := `{"name":"` + name + `","composeYaml":` + jsonString(compose) + `,"targetNode":"n1","exposeLan":true`
	if port != "" {
		b += `,"webPort":` + port
	}
	return b + "}"
}

// keysOf decodes a JSON object's keys.
func keysOf(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return m
}

// TC-1089-01, TC-1089-02, TC-1089-03: create stores and returns the port,
// at its bounds, and stores none when it is absent or null.
func TestCreateApp_WebPort(t *testing.T) {
	f := newWebPortFixture(t)
	for _, c := range []struct {
		name, port string
		want       int
	}{
		{"port-8080", "8080", 8080}, // TC-1089-01
		{"port-low", "1", 1},        // TC-1089-03
		{"port-high", "65535", 65535},
		{"port-absent", "", 0}, // TC-1089-02
		{"port-null", "null", 0},
	} {
		w := f.do(t, http.MethodPost, "/api/apps", createBody(c.name, c.port), f.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: want 201, got %d (%s)", c.name, w.Code, w.Body.String())
		}
		created := decodeBody[apps.App](t, w.Body.String())
		views := map[string]string{"create": w.Body.String()}
		if g := f.do(t, http.MethodGet, "/api/apps/"+created.ID, "", f.cookie); g.Code == http.StatusOK {
			views["get"] = g.Body.String()
		} else {
			t.Fatalf("GET %s: %d", created.ID, g.Code)
		}
		var list []json.RawMessage
		if err := json.Unmarshal(f.do(t, http.MethodGet, "/api/apps", "", f.cookie).Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		for _, raw := range list {
			if decodeBody[apps.App](t, string(raw)).ID == created.ID {
				views["list"] = string(raw)
			}
		}
		for where, body := range views {
			keys := keysOf(t, body)
			got, has := keys["publishedPort"]
			switch {
			case c.want == 0 && has:
				t.Errorf("%s %s: publishedPort %s, want no key", c.name, where, got)
			case c.want != 0 && string(got) != fmt.Sprint(c.want):
				t.Errorf("%s %s: publishedPort %s, want %d", c.name, where, got, c.want)
			}
			if _, has := keys["webTls"]; has {
				t.Errorf("%s %s carries webTls: %s", c.name, where, body)
			}
		}
		if len(views) != 3 {
			t.Errorf("%s: missing from GET /api/apps", c.name)
		}
		if row := f.row(t, created.ID); row.PublishedPort != c.want || row.WebTLS {
			t.Errorf("%s: row port=%d webTls=%v, want %d and false", c.name, row.PublishedPort, row.WebTLS, c.want)
		}
	}
}

// TC-1089-04: every malformed port is a coded 400 and no app exists.
func TestCreateApp_WebPortRefused(t *testing.T) {
	f := newWebPortFixture(t)
	for _, v := range []string{`0`, `-1`, `65536`, `"8080"`, `80.5`, `8080.0`, `true`, `{}`} {
		w := f.do(t, http.MethodPost, "/api/apps", createBody("refused", v), f.cookie)
		assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortInvalid, msgWebPortInvalid, "POST /api/apps")
	}
	if all, _ := f.appsStore.List(f.ctx); len(all) != 0 {
		t.Errorf("%d apps exist after refusals", len(all))
	}
}

// TC-1089-05: an out-of-range port is judged after the existing checks, so
// an earlier invalid field answers with its own message.
func TestCreateApp_WebPortOrdering(t *testing.T) {
	f := newWebPortFixture(t)
	for _, c := range []struct{ body, want string }{
		{`{"name":"","composeYaml":"services: {}","targetNode":"n1","webPort":0}`, "name is required"},
		{`{"name":"x","composeYaml":"services: {}","targetNode":"ghost","webPort":0}`, "target node not registered"},
	} {
		w := f.do(t, http.MethodPost, "/api/apps", c.body, f.cookie)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: got %d %s, want 400 %q", c.body, w.Code, w.Body.String(), c.want)
		}
	}
	if all, _ := f.appsStore.List(f.ctx); len(all) != 0 {
		t.Errorf("%d apps exist after refusals", len(all))
	}
}

const webPortAppID = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"

// TC-1089-06: a new compose with a port sets both, and the leaf goes out
// with the new port.
func TestPutCompose_NewComposeAndWebPort(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 0)
	j := f.put(t, webPortAppID, `{"composeYaml":`+jsonString(customNew)+`,"webPort":9090}`, http.StatusAccepted)
	if j.Kind != "app.edit" || string(j.Spec) != `{"appId":"`+webPortAppID+`"}` {
		t.Errorf("job = %s %s, want app.edit keyed only by appId", j.Kind, j.Spec)
	}
	row := f.row(t, webPortAppID)
	if row.ComposeYAML != customNew || row.PublishedPort != 9090 || row.PreviousPublishedPort != 0 {
		t.Errorf("row compose new=%v port=%d previous port=%d, want true, 9090, 0",
			row.ComposeYAML == customNew, row.PublishedPort, row.PreviousPublishedPort)
	}
	if cmd := f.leaf(t); cmd.UpstreamPort != 9090 || cmd.AppID != webPortAppID {
		t.Errorf("leaf = %+v, want port 9090", cmd)
	}
	if got := f.stepResult(t, j.ID, "persist")["webPort"]; got != float64(9090) {
		t.Errorf("persist result webPort = %v, want 9090", got)
	}
}

// TC-1089-07: a new compose without a port leaves the port as it was, and
// the previous record keeps it too.
func TestPutCompose_NewComposeKeepsThePort(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 8080)
	j := f.put(t, webPortAppID, composeYAMLBody(t, customNew), http.StatusAccepted)
	row := f.row(t, webPortAppID)
	if row.ComposeYAML != customNew || row.PublishedPort != 8080 || row.PreviousPublishedPort != 8080 {
		t.Errorf("row port=%d previous=%d, want 8080 and 8080", row.PublishedPort, row.PreviousPublishedPort)
	}
	if _, has := f.stepResult(t, j.ID, "persist")["webPort"]; has {
		t.Error("persist result names a port no one declared")
	}
}

// TC-1089-08: the installed compose with a different port is a port-only
// edit: the port moves, the compose and the previous record do not.
func TestPutCompose_PortOnlyEdit(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 7070)
	if err := f.appsStore.EditCompose(f.ctx, webPortAppID, apps.ComposeHash(customOld), customNew, 8080, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	before := f.row(t, webPortAppID)
	j := f.put(t, webPortAppID, `{"composeYaml":`+jsonString(customNew)+`,"webPort":9090}`, http.StatusAccepted)
	if j.Kind != "app.edit" {
		t.Errorf("job kind %s", j.Kind)
	}
	after := f.row(t, webPortAppID)
	if after.PublishedPort != 9090 || after.ComposeYAML != before.ComposeYAML || after.ComposeSHA256 != before.ComposeSHA256 ||
		after.PreviousComposeYAML != customOld || after.PreviousPublishedPort != 7070 {
		t.Errorf("after = port %d, compose same %v, previous compose same %v, previous port %d; want 9090, true, true, 7070",
			after.PublishedPort, after.ComposeSHA256 == before.ComposeSHA256, after.PreviousComposeYAML == customOld, after.PreviousPublishedPort)
	}
	if cmd := f.leaf(t); cmd.UpstreamPort != 9090 {
		t.Errorf("leaf port %d, want 9090", cmd.UpstreamPort)
	}
	if log := f.jobLog(t, j.ID); !strings.Contains(log, "web port set to 9090 (was 8080)") {
		t.Errorf("job log lacks the port change:\n%s", log)
	}
}

// TC-1089-09: the installed compose with no port, null, or the stored port
// is the 200 no-op: no job, nothing held.
func TestPutCompose_SamePortIsANoOp(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 8080)
	for _, extra := range []string{`,"webPort":8080`, ``, `,"webPort":null`} {
		w := f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose", `{"composeYaml":`+jsonString(customOld)+extra+`}`, f.cookie)
		if w.Code != http.StatusOK {
			t.Errorf("%q: want 200, got %d (%s)", extra, w.Code, w.Body.String())
		}
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("%d edits held", n)
	}
}

// TC-1089-10: a malformed port beside a new compose is a coded 400, with no
// job, nothing held and the row as it was.
func TestPutCompose_WebPortRefused(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 8080)
	before := f.row(t, webPortAppID)
	for _, v := range []string{`0`, `-1`, `65536`, `"8080"`, `80.5`} {
		w := f.do(t, http.MethodPut, "/api/apps/"+webPortAppID+"/compose", `{"composeYaml":`+jsonString(customNew)+`,"webPort":`+v+`}`, f.cookie)
		assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortInvalid, msgWebPortInvalid, "PUT /api/apps/{id}/compose", "app_id")
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
	if n := f.srv.composeStash.Len(); n != 0 {
		t.Errorf("%d edits held", n)
	}
	if after := f.row(t, webPortAppID); after.ComposeSHA256 != before.ComposeSHA256 || after.PublishedPort != 8080 {
		t.Errorf("row changed: %+v", after)
	}
}

// TC-1089-11: a port without composeYaml — beside sha256, beside source, or
// alone — is told it goes only beside composeYaml (F-1089-02), on either kind
// of app.
func TestPutCompose_WebPortWithoutCompose(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 8080)
	seedUpgradeApp(t, f.apiFixture, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	for _, id := range []string{webPortAppID, "cat"} {
		for _, body := range []string{
			`{"sha256":"` + apps.ComposeHash(customOld) + `","webPort":9090}`,
			`{"source":"catalog","webPort":9090}`,
			`{"webPort":9090}`,
		} {
			w := f.do(t, http.MethodPut, "/api/apps/"+id+"/compose", body, f.cookie)
			assertWebPortRefusal(t, f.apiFixture, w, w.Body.Bytes(), codeWebPortWithoutCompose, msgWebPortWithoutCompose, "PUT /api/apps/{id}/compose", "app_id")
		}
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
	if p := f.row(t, webPortAppID).PublishedPort; p != 8080 {
		t.Errorf("custom port %d, want 8080", p)
	}
	if p := f.row(t, "cat").PublishedPort; p != 1234 {
		t.Errorf("catalog port %d, want 1234", p)
	}
}

// TC-1089-12: a catalog app's compose and port are not the owner's to send.
func TestPutCompose_WebPortOnACatalogApp(t *testing.T) {
	f := newWebPortFixture(t)
	seedUpgradeApp(t, f.apiFixture, "cat", "vw", "vaultwarden", "services: {old: {}}\n", 3)
	w := f.do(t, http.MethodPut, "/api/apps/cat/compose", `{"composeYaml":`+jsonString(customNew)+`,"webPort":9090}`, f.cookie)
	if w.Code != http.StatusConflict || decodeBody[map[string]string](t, w.Body.String())["error"] != apps.ErrEditCatalogApp.Error() {
		t.Errorf("want 409 with ErrEditCatalogApp, got %d %s", w.Code, w.Body.String())
	}
	assertNoComposeJob(t, f.apiFixture, f.deploys)
	if p := f.row(t, "cat").PublishedPort; p != 1234 {
		t.Errorf("catalog port %d, want 1234", p)
	}
}

// TC-1089-13: POST /api/jobs cannot set a port. A spec naming one is
// refused by the saga's strict decode; one without fails because nothing was
// held for it. Neither moves the port.
func TestJobs_WebPortCannotBeForged(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 8080)
	for _, c := range []struct{ spec, wantErr string }{
		{`{"appId":"` + webPortAppID + `","webPort":9999}`, `unknown field "webPort"`},
		{`{"appId":"` + webPortAppID + `"}`, "the submitted compose is not held"},
	} {
		w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"app.edit","spec":`+c.spec+`}`, f.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: want 201, got %d (%s)", c.spec, w.Code, w.Body.String())
		}
		j := f.runJob(t, w.Body.String())
		if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, c.wantErr) {
			t.Errorf("%s: job %s %q, want failed with %q", c.spec, j.Status, j.Error, c.wantErr)
		}
		if p := f.row(t, webPortAppID).PublishedPort; p != 8080 {
			t.Errorf("%s: port %d, want 8080", c.spec, p)
		}
	}
}

// TC-1089-16: a port declared at create reaches the first deploy's leaf,
// with both names and plain HTTP upstream.
func TestCreateApp_WebPortReachesTheFirstDeploysLeaf(t *testing.T) {
	f := newWebPortFixture(t)
	w := f.do(t, http.MethodPost, "/api/apps", createBody("web", "8080"), f.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := decodeBody[apps.App](t, w.Body.String()).ID
	d := f.do(t, http.MethodPost, "/api/apps/"+id+"/deploy", "", f.cookie)
	if d.Code != http.StatusAccepted {
		t.Fatalf("deploy: %d %s", d.Code, d.Body.String())
	}
	j := f.runJob(t, d.Body.String())
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("deploy %s: %s", j.Status, j.Error)
	}
	tailnet, lan := mesh.AppRouteHosts(webPortCluster, "web", true)
	cmd := f.leaf(t)
	if cmd.UpstreamPort != 8080 || cmd.UpstreamTLS || cmd.TailnetFQDN != tailnet || cmd.LANFQDN != lan || lan == "" {
		t.Errorf("leaf = %+v, want port 8080, plain HTTP, %s and %s", cmd, tailnet, lan)
	}
	if log := f.jobLog(t, j.ID); strings.Contains(log, "no published port") {
		t.Errorf("leaf step skipped:\n%s", log)
	}
}

// TC-1089-17: a revert restores the port recorded with the compose it
// re-applies — none, for a custom app's original — and re-applying the newer
// compose by hash restores the declared port (F-1089-03).
func TestPutCompose_RevertTakesThePortWithTheCompose(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 0)
	f.put(t, webPortAppID, `{"composeYaml":`+jsonString(customNew)+`,"webPort":9090}`, http.StatusAccepted)

	f.put(t, webPortAppID, shaBody(customOld), http.StatusAccepted)
	row := f.row(t, webPortAppID)
	if row.ComposeYAML != customOld || row.PublishedPort != 0 || row.PreviousPublishedPort != 9090 {
		t.Errorf("after revert: port %d previous %d, want 0 and 9090", row.PublishedPort, row.PreviousPublishedPort)
	}
	if _, has := keysOf(t, f.do(t, http.MethodGet, "/api/apps/"+webPortAppID, "", f.cookie).Body.String())["publishedPort"]; has {
		t.Error("GET shows a publishedPort after the revert to no port")
	}

	f.put(t, webPortAppID, shaBody(customNew), http.StatusAccepted)
	if row := f.row(t, webPortAppID); row.ComposeYAML != customNew || row.PublishedPort != 9090 {
		t.Errorf("after re-apply: port %d, want 9090", row.PublishedPort)
	}
}

// TC-1089-18: a row as the previous release wrote it behaves as before until
// a port is declared, and then gets its leaf.
func TestPutCompose_RowFromThePreviousRelease(t *testing.T) {
	f := newWebPortFixture(t)
	f.seedCustom(t, webPortAppID, customOld, 0)
	if _, has := keysOf(t, f.do(t, http.MethodGet, "/api/apps/"+webPortAppID, "", f.cookie).Body.String())["publishedPort"]; has {
		t.Error("GET shows a publishedPort for a row with none")
	}
	d := f.do(t, http.MethodPost, "/api/apps/"+webPortAppID+"/deploy", "", f.cookie)
	j := f.runJob(t, d.Body.String())
	if j.Status != jobs.StatusSucceeded || !strings.Contains(f.jobLog(t, j.ID), "no published port — skipping proxy leaf") {
		t.Errorf("deploy %s: want the leaf skipped, log:\n%s", j.Status, f.jobLog(t, j.ID))
	}
	select {
	case cmd := <-f.leaves:
		t.Errorf("a leaf went out for an app with no port: %+v", cmd)
	default:
	}

	f.put(t, webPortAppID, `{"composeYaml":`+jsonString(customOld)+`,"webPort":8080}`, http.StatusAccepted)
	if p := f.row(t, webPortAppID).PublishedPort; p != 8080 {
		t.Errorf("port %d, want 8080", p)
	}
	if cmd := f.leaf(t); cmd.UpstreamPort != 8080 {
		t.Errorf("leaf port %d, want 8080", cmd.UpstreamPort)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
