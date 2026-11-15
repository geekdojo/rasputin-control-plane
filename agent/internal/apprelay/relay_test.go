package apprelay

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// TC-1081-22: the HTTP contract, over a fake forwarder. Every error body
// carries a code, a sentence and a correlation id (F-1081-02); a body over
// the limit or malformed is refused with no forward.
func TestRoutes_HTTPContract(t *testing.T) {
	type call struct {
		method, body string
		reply        proto.AppSecretReply
		status       int
		code         string
	}
	ok := proto.AppSecretReply{Code: proto.AppSecretOK, Value: "v"}
	for name, c := range map[string]call{
		"POST created":       {http.MethodPost, `{"value":"v"}`, ok, http.StatusCreated, ""},
		"POST exists":        {http.MethodPost, `{"value":"v"}`, proto.AppSecretReply{Code: proto.AppSecretExists, Message: "The secret already exists."}, http.StatusConflict, proto.AppSecretExists},
		"PUT replaced":       {http.MethodPut, `{"value":"v"}`, ok, http.StatusOK, ""},
		"PUT absent":         {http.MethodPut, `{"value":"v"}`, proto.AppSecretReply{Code: proto.AppSecretNotFound, Message: "The secret does not exist."}, http.StatusNotFound, proto.AppSecretNotFound},
		"GET read":           {http.MethodGet, "", ok, http.StatusOK, ""},
		"GET absent":         {http.MethodGet, "", proto.AppSecretReply{Code: proto.AppSecretNotFound, Message: "The secret does not exist."}, http.StatusNotFound, proto.AppSecretNotFound},
		"DELETE present":     {http.MethodDelete, "", ok, http.StatusNoContent, ""},
		"DELETE absent":      {http.MethodDelete, "", ok, http.StatusNoContent, ""},
		"forbidden":          {http.MethodGet, "", proto.AppSecretReply{Code: proto.AppSecretForbidden, Message: "Refused."}, http.StatusForbidden, proto.AppSecretForbidden},
		"api unavailable":    {http.MethodGet, "", proto.AppSecretReply{Code: proto.AppSecretUnavailable, Message: "Later."}, http.StatusServiceUnavailable, proto.AppSecretUnavailable},
		"unsupported method": {http.MethodPatch, "", ok, http.StatusMethodNotAllowed, proto.AppSecretMethodNotAllowed},
		"too large":          {http.MethodPost, `{"value":"` + strings.Repeat("x", proto.AppRelayMaxValueBytes+1) + `"}`, ok, http.StatusRequestEntityTooLarge, proto.AppSecretTooLarge},
		"body over the cap":  {http.MethodPost, strings.Repeat(" ", maxBodyBytes+1) + `{"value":"v"}`, ok, http.StatusRequestEntityTooLarge, proto.AppSecretTooLarge},
		"malformed JSON":     {http.MethodPut, `{"value":`, ok, http.StatusBadRequest, proto.AppSecretInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			fwd := &fakeForwarder{reply: c.reply}
			srv := httptest.NewServer(routes(appA, fwd, counter()))
			defer srv.Close()
			req, _ := http.NewRequest(c.method, srv.URL+"/v1/secrets/k", strings.NewReader(c.body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != c.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, c.status)
			}
			var body map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if c.code != "" {
				if body["code"] != c.code || body["correlationId"] == "" || !strings.HasSuffix(body["message"], ".") {
					t.Errorf("error body %v, want code %s with a sentence and a correlation id", body, c.code)
				}
			}
			agentRefusal := c.status == http.StatusMethodNotAllowed || c.status == http.StatusRequestEntityTooLarge || c.status == http.StatusBadRequest
			if agentRefusal && len(fwd.seen()) != 0 {
				t.Errorf("an agent-side refusal forwarded %d calls", len(fwd.seen()))
			}
			if name == "GET read" && body["value"] != "v" {
				t.Errorf("read body %v", body)
			}
		})
	}
}

func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// TC-1081-21: a call on A's socket whose path, headers or body name B is
// published as A's, on the node's own subject, asking for a reply under the
// node's reply prefix. Before Attach it is 503; an api that does not answer
// within the bound is 503 with one WARN.
func TestRelay_StampsTheSocketsApp(t *testing.T) {
	nc := startNATS(t)
	log, rec := logkittest.New()
	relay, err := NewRelay("n1", 300*time.Millisecond, log)
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)
	m, _ := newTestManager(t, filepath.Join(shortDir(t), "relay"), relay)
	installed(t, m, ca, appA, 1)
	mnt, _ := m.MountDir(appA)
	c := client(filepath.Join(mnt, proto.AppRelaySocketName), ca.pool(), proto.AppRelayServerName, 0)

	status, body, err := do(t, c, http.MethodGet, "k", "")
	if err != nil || status != http.StatusServiceUnavailable || body["code"] != proto.AppSecretUnavailable || body["correlationId"] == "" {
		t.Fatalf("before Attach: %d %v %v; want 503 unavailable with a correlation id", status, body, err)
	}

	relay.Attach(nc)
	type got struct {
		subject, reply string
		call           proto.AppSecretCall
	}
	calls := make(chan got, 4)
	sub, err := nc.Subscribe(proto.AppSecretCallFilter, func(msg *nats.Msg) {
		var call proto.AppSecretCall
		_ = json.Unmarshal(msg.Data, &call)
		calls <- got{msg.Subject, msg.Reply, call}
		b, _ := json.Marshal(proto.AppSecretReply{Code: proto.AppSecretOK, CorrelationID: "api"})
		_ = msg.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+proto.AppRelayServerName+"/v1/secrets/k?app="+appB,
		strings.NewReader(`{"value":"v","appId":"`+appB+`"}`))
	req.Header.Set("X-App-Id", appB)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	g := <-calls
	if g.call.AppID != appA || g.subject != proto.AppSecretCallSubject("n1") || !strings.HasPrefix(g.reply, proto.AppSecretReplyPrefix("n1")) {
		t.Errorf("published %+v on %s with reply %s; want app A on n1's subject, reply under n1's prefix", g.call, g.subject, g.reply)
	}

	_ = sub.Unsubscribe()
	silent, err := nc.SubscribeSync(proto.AppSecretCallFilter)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Unsubscribe() }()
	status, body, err = do(t, c, http.MethodGet, "k", "")
	if err != nil || status != http.StatusServiceUnavailable || body["correlationId"] == "" {
		t.Fatalf("no api answer: %d %v %v; want 503", status, body, err)
	}
	if warns := rec.AtLevel(slog.LevelWarn); len(warns) != 1 {
		t.Errorf("%d WARN records, want 1", len(warns))
	} else if id, _ := logkittest.Attr(warns[0], "app_id"); id != appA {
		t.Errorf("WARN names %q", id)
	}
}
