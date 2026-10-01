package bustls_test

// A node that registers at the first moment the bus admits it is recorded
// (geekdojo/geekdojo-brain#623). The real rasputin-api binary, with the real
// auth callout: the moment its log says the responder is active, eight bus
// clients holding bound join tokens connect at once, and each publishes one
// registration and never re-sends. Every one of them must reach inventory.
//
// Why test clients and not the real agent: the agent's fixed reconnect wait
// cannot aim a registration at the start-up window, and a client that sends
// exactly once is what makes a lost registration stay lost.
//
// How "never recorded" is a fact and not a timeout: after the api's HTTP
// listener is up (every start-up subscriber exists by then, in either
// ordering), a ninth sentinel node registers. Inventory handles registrations
// in arrival order on one subscription, and every early client flushed its
// publish before the sentinel connected, so once the sentinel is recorded any
// early registration the api received has been recorded too. One that is
// still missing was dropped.

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls/bustlstest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// earlyClients is how many nodes register at the admission moment.
const earlyClients = 8

const recordedLine = "inventory: registration recorded"

func earlyNodeID(i int) string { return fmt.Sprintf("n-early-%d", i) }

const sentinelNode = "n-sentinel"

func registrationToken(id string) string { return "reg-gap-token-" + id }

// busClientTLS trusts the api's own persisted bus certificate.
func busClientTLS(t *testing.T, dataDir string) nats.Option {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, "bus", bustls.CertFileName))
	if err != nil {
		t.Fatalf("read the api's bus certificate: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("the api's bus certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the api's bus certificate: %v", err)
	}
	return nats.Secure(bustlstest.ClientConfig(leaf))
}

// registerOnce connects as id, publishes one registration, flushes it to the
// server and closes. A connect error is returned as such, so the test can
// tell "not admitted" apart from "admitted and never recorded".
func registerOnce(url, id string, secure nats.Option) (connectErr, publishErr error) {
	nc, err := nats.Connect(url, secure,
		nats.UserInfo(id, registrationToken(id)),
		nats.MaxReconnects(0),
		nats.Timeout(10*time.Second)) // bounds the one dial
	if err != nil {
		return err, nil
	}
	defer nc.Close()
	ev := proto.NodeRegisteredEvt{NodeID: id, Role: proto.RoleCompute, Hostname: id + ".test", AgentVersion: "reg-gap-test"}
	data, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	if err := nc.Publish(proto.NodeRegisteredSubject(id), data); err != nil {
		return nil, err
	}
	// The server has processed the PUB once the PONG comes back.
	if err := nc.FlushTimeout(10 * time.Second); err != nil {
		return nil, err
	}
	return nil, nil
}

func recordedFor(a *apiProc, id string) bool {
	return a.count(recordedLine, "node_id="+id+" ") > 0
}

// TC-623-12, TC-623-13: every node admitted at the earliest moment, which
// publishes its registration exactly once, is recorded by inventory.
func TestFunctional_RegistrationsDuringStartupAreRecorded(t *testing.T) {
	skipShort(t)
	var preseed []busauth.PreseedToken
	ids := []string{sentinelNode}
	for i := 1; i <= earlyClients; i++ {
		ids = append(ids, earlyNodeID(i))
	}
	for _, id := range ids {
		preseed = append(preseed, busauth.PreseedToken{
			Hash: busauth.HashToken(registrationToken(id)), NodeID: id, Label: id, Role: proto.RoleCompute,
		})
	}
	api, _ := startAPI(t, apiOpts{preseed: preseed, noWait: true})
	url := fmt.Sprintf("nats://127.0.0.1:%d", api.natsPort)

	// The admission fact: the responder answers callouts from here on.
	api.waitLog(t, "the auth-callout responder", "busauth: auth-callout responder active")
	secure := busClientTLS(t, api.dataDir)

	type result struct {
		id                     string
		connectErr, publishErr error
	}
	results := make([]result, earlyClients)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 1; i <= earlyClients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id := earlyNodeID(i)
			c, p := registerOnce(url, id, secure)
			results[i-1] = result{id, c, p}
		}(i)
	}
	close(start)
	wg.Wait()
	for _, r := range results {
		if r.connectErr != nil {
			t.Fatalf("%s was not admitted to the bus: %v", r.id, r.connectErr)
		}
		if r.publishErr != nil {
			t.Fatalf("%s was admitted but its registration did not reach the server: %v", r.id, r.publishErr)
		}
	}

	// Every start-up subscriber exists once HTTP is up; then the sentinel.
	api.waitLog(t, "the HTTP listener", "rasputin-api: http listening on")
	if c, p := registerOnce(url, sentinelNode, secure); c != nil || p != nil {
		t.Fatalf("the sentinel did not register: connect %v, publish %v", c, p)
	}
	waitFact(t, "the sentinel's registration recorded", &api.changed, func() bool {
		if api.hasExited() {
			t.Fatalf("the api exited\n%s", api.log())
		}
		return recordedFor(api, sentinelNode)
	}, api.log)

	var lost []string
	for _, r := range results {
		if !recordedFor(api, r.id) {
			lost = append(lost, r.id)
		}
	}
	if len(lost) > 0 {
		sort.Strings(lost)
		t.Fatalf("admitted and published but never recorded: %s", strings.Join(lost, ", "))
	}
}
