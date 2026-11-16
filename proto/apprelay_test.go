package proto

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TC-1081-01: switched off, a deploy command's bytes carry no relay key; on,
// the only difference is a trailing ,"relay":true.
func TestAppDeployCmd_RelayBytes(t *testing.T) {
	cmd := AppDeployCmd{AppID: "01J9ZK3Q0M8X7Y6W5V4T3S2R1A", Name: "kuma", ComposeYAML: "services: {}\n",
		WorkBudgetSeconds: 300, SecretEnv: AppSecretEnv{"RASPUTIN_SECRET_X": "v"}}
	off, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(off, []byte("relay")) {
		t.Errorf("Relay:false marshals a relay key: %s", off)
	}
	cmd.Relay = true
	on, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(off[:len(off)-1]) + `,"relay":true}`; string(on) != want {
		t.Errorf("Relay:true = %s, want %s", on, want)
	}
}

// TC-1081-25: the subjects, the floor, and log values that leave out values.
func TestAppRelay_SubjectsFloorAndRedaction(t *testing.T) {
	for got, want := range map[string]string{
		AppRelaySubject("n1"):      "rasputin.node.n1.cmd.app.relay",
		AppSecretCallSubject("n1"): "rasputin.node.n1.relay.app.secret",
		AppSecretCallFilter:        "rasputin.node.*.relay.app.secret",
		AppSecretReplyPrefix("n1"): "rasputin.node.n1.cmd.app.relay.reply.",
	} {
		if got != want {
			t.Errorf("subject %q, want %q", got, want)
		}
	}
	// The agent's app.relay subscription is the literal verb subject, which a
	// reply subject under the prefix never equals.
	if reply := AppSecretReplyPrefix("n1") + "TOKEN"; reply == AppRelaySubject("n1") || !strings.HasPrefix(reply, NodeCmdFilter("n1")[:len(NodeCmdFilter("n1"))-1]) {
		t.Errorf("reply %q matches the verb, or is not on the node's command lane", reply)
	}
	if node, ok := AppSecretCallNode(AppSecretCallSubject("n1")); !ok || node != "n1" {
		t.Errorf("AppSecretCallNode = %q, %v", node, ok)
	}
	for _, bad := range []string{"rasputin.node.a.b.relay.app.secret", "rasputin.node..relay.app.secret", "rasputin.node.*.relay.app.secret", "x"} {
		if _, ok := AppSecretCallNode(bad); ok {
			t.Errorf("AppSecretCallNode(%q) accepted", bad)
		}
	}
	if floor, ok := VerbMinAgentVersion(AppRelayVerb); !ok || floor == "" || strings.HasPrefix(floor, "v") {
		t.Errorf("app.relay floor = %q, %v; want a bare CalVer entry (F-1081-03)", floor, ok)
	}

	const value = "sentinel-value-1081-25"
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("call", "call", AppSecretCall{AppID: "A", Op: AppSecretCreate, Name: "k", Value: value})
	log.Info("reply", "reply", AppSecretReply{Code: AppSecretOK, CorrelationID: "c", Value: value})
	log.Info("cmd", "cmd", AppRelayCmd{AppID: "A", Op: AppRelayInstall, CertPEM: []byte("-----BEGIN CERTIFICATE-----")})
	if strings.Contains(buf.String(), value) || strings.Contains(buf.String(), "BEGIN") {
		t.Errorf("a value or certificate reached the log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"correlationId":"c"`) || !strings.Contains(buf.String(), `"name":"k"`) {
		t.Errorf("the log values lost their fields: %s", buf.String())
	}
}
