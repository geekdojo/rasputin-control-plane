package apps_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apprelay"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// geekdojo/geekdojo-brain#1081: the push family with the real relay issuer
// against a fake agent on node n.

// relayFailure is how the fake agent, or the signer, fails one issue.
type relayFailure string

const (
	failNone             relayFailure = ""
	failNoResponder      relayFailure = "no responder on app.relay"
	failPrepareRefused   relayFailure = "prepare ack OK:false"
	failMalformedKey     relayFailure = "malformed PublicKeyDER"
	failSign             relayFailure = "sign error"
	failInstallTransport relayFailure = "install transport error"
	failInstallRefused   relayFailure = "install ack OK:false"
)

// nodeAgent is a fake agent on node n: it answers app.relay as fail says,
// and observes (without answering) every deploy command, recording the order
// of everything it saw.
type nodeAgent struct {
	mu     sync.Mutex
	events []string
	der    []byte
}

func (a *nodeAgent) note(e string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
}

func (a *nodeAgent) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events)
}

func (a *nodeAgent) deploys() int {
	n := 0
	for _, e := range a.seen() {
		if e == "deploy" {
			n++
		}
	}
	return n
}

func startNodeAgent(t *testing.T, nc *nats.Conn, fail relayFailure) *nodeAgent {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	a := &nodeAgent{der: der}
	if fail != failNoResponder {
		sub, err := nc.Subscribe(proto.AppRelaySubject("n"), func(m *nats.Msg) {
			var cmd proto.AppRelayCmd
			_ = json.Unmarshal(m.Data, &cmd)
			a.note(cmd.Op)
			ack := proto.AppRelayAck{OK: true}
			switch {
			case cmd.Op == proto.AppRelayPrepare && fail == failPrepareRefused,
				cmd.Op == proto.AppRelayInstall && fail == failInstallRefused:
				ack = proto.AppRelayAck{Detail: "refused by the fake agent"}
			case cmd.Op == proto.AppRelayPrepare && fail == failMalformedKey:
				ack.PublicKeyDER = []byte("not a key")
			case cmd.Op == proto.AppRelayPrepare:
				ack.PublicKeyDER = der
			}
			b, _ := json.Marshal(ack)
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
		if fail == failInstallTransport {
			// Gone after the prepare: the install draws no responder.
			if err := sub.AutoUnsubscribe(1); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	for _, subject := range []string{proto.AppDeploySubject("n"), proto.AppDeploySecretsSubject("n")} {
		sub, err := nc.Subscribe(subject, func(*nats.Msg) { a.note("deploy") })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	return a
}

// countingSigner is the CA, counting its signatures, or failing them.
type countingSigner struct {
	ca  *tlsca.CA
	n   int
	err error
}

func (s *countingSigner) SignLeaf(spec tlsca.LeafSpec, pub crypto.PublicKey) ([]byte, error) {
	s.n++
	if s.err != nil {
		return nil, s.err
	}
	return s.ca.SignLeaf(spec, pub)
}

// relayIdentity is the switch granting tiles, over the real issuer on nc.
func relayIdentity(t *testing.T, nc *nats.Conn, inv *inventory.Store, signer *countingSigner, tiles ...string) apps.AppIdentity {
	t.Helper()
	iss, err := apprelay.NewIssuer(apprelay.IssuerDeps{Bus: nc, Signer: signer, CACert: signer.ca.Cert, CAPEM: signer.ca.CertPEM, Silence: inv})
	if err != nil {
		t.Fatal(err)
	}
	id, err := apps.NewAppIdentity(tiles, iss)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TC-1081-03: a granted app's deploy goes to the subject its ungranted golden
// records, with the golden's bytes and ,"relay":true appended; prepare, sign
// and install each ran once, before the command was published.
func TestGrantedDeploy_DiffersFromTheGoldenOnlyByRelay(t *testing.T) {
	ca := tlscatest.Controlplane(t, filepath.Join(t.TempDir(), "trust"))
	for _, name := range []string{"plain-tile", "secret-compose"} {
		t.Run(name, func(t *testing.T) {
			signer := &countingSigner{ca: ca}
			var agent *nodeAgent
			build := func(store *apps.Store, inv *inventory.Store, nc *nats.Conn, src apps.SecretSource) (jobs.Workflow, error) {
				agent = startNodeAgent(t, nc, failNone)
				return apps.DeployWorkflow(store, inv, nc, nil, src, relayIdentity(t, nc, inv, signer, "minecraft", "karakeep"))
			}
			got, data := apps.DeployGoldenWire(t, build, name)
			want, err := os.ReadFile(filepath.Join(apps.DeployGoldenDir, name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			wantSubject, wantSum, _ := strings.Cut(strings.TrimSpace(string(want)), "\n")
			gotSubject, _, _ := strings.Cut(got, "\n")
			if gotSubject != wantSubject {
				t.Errorf("subject = %s, want the golden's %s", gotSubject, wantSubject)
			}
			base, ok := strings.CutSuffix(string(data), `,"relay":true}`)
			if !ok {
				t.Fatalf("the command does not end in ,\"relay\":true: %s", data)
			}
			sum := sha256.Sum256([]byte(base + "}"))
			if hex.EncodeToString(sum[:]) != wantSum {
				t.Errorf("without ,\"relay\":true the bytes are not the golden's")
			}
			if seen := agent.seen(); !slices.Equal(seen, []string{"prepare", "install", "deploy"}) || signer.n != 1 {
				t.Errorf("the agent saw %v with %d signs; want prepare, install, deploy and one sign", seen, signer.n)
			}
		})
	}
}

// pushSaga is one saga of the push family run for a granted app.
type pushSaga struct {
	name string
	seed func(t *testing.T) (*apps.Store, *inventory.Store)
	run  func(t *testing.T, store *apps.Store, inv *inventory.Store, nc *nats.Conn, id apps.AppIdentity) apps.WorkflowRun
}

func pushSagas() []pushSaga {
	spec := `{"appId":"` + apps.TestAppID + `"}`
	return []pushSaga{
		{"deploy", func(t *testing.T) (*apps.Store, *inventory.Store) { return apps.SeedUpgradeApp(t, apps.TestAppID) },
			func(t *testing.T, store *apps.Store, inv *inventory.Store, nc *nats.Conn, id apps.AppIdentity) apps.WorkflowRun {
				w, err := apps.DeployWorkflow(store, inv, nc, nil, apps.TestSource(t), id)
				if err != nil {
					t.Fatal(err)
				}
				return apps.RunWorkflow(t, w, nc, spec, "job-1081")
			}},
		{"revert", apps.UpgradedToV2,
			func(t *testing.T, store *apps.Store, inv *inventory.Store, nc *nats.Conn, id apps.AppIdentity) apps.WorkflowRun {
				apps.FakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
				w, err := apps.RevertWorkflow(store, inv, nc, nil, apps.TestSource(t), id)
				if err != nil {
					t.Fatal(err)
				}
				return apps.RunWorkflow(t, w, nc, apps.RevertSpecJSON(apps.TestAppID, apps.ComposeV1), "job-1081")
			}},
		{"edit", func(t *testing.T) (*apps.Store, *inventory.Store) { return apps.SeedUpgradeApp(t, apps.TestAppID) },
			func(t *testing.T, store *apps.Store, inv *inventory.Store, nc *nats.Conn, id apps.AppIdentity) apps.WorkflowRun {
				stash := apps.NewComposeStash()
				if err := stash.Put("job-1081", apps.HeldEdit{ComposeYAML: apps.ComposeV2}); err != nil {
					t.Fatal(err)
				}
				w, err := apps.EditWorkflow(store, inv, nc, nil, stash, apps.TestSource(t), apps.TestSecretDeps(), id)
				if err != nil {
					t.Fatal(err)
				}
				return apps.RunWorkflow(t, w, nc, spec, "job-1081")
			}},
		{"upgrade", func(t *testing.T) (*apps.Store, *inventory.Store) { return apps.SeedUpgradeApp(t, apps.TestAppID) },
			func(t *testing.T, store *apps.Store, inv *inventory.Store, nc *nats.Conn, id apps.AppIdentity) apps.WorkflowRun {
				apps.FakePullAgent(t, nc, proto.AppPullAck{OK: true}, nil)
				w, err := apps.UpgradeWorkflow(store, inv, nc, nil, apps.LookupOf(apps.UpgradeTile(apps.ComposeV2), 2), apps.TestSource(t), apps.TestSecretDeps(), id)
				if err != nil {
					t.Fatal(err)
				}
				return apps.RunWorkflow(t, w, nc, spec, "job-1081")
			}},
	}
}

// TC-1081-04 and TC-1081-26 (an agent below the app.relay floor): every issue
// failure, on every push path of a granted app, refuses the push with an
// error naming the app; nothing is published on either deploy verb; a plain
// deploy is not marked DEPLOYING; no job log line or step result carries key
// or certificate bytes. Edit is a custom-app saga: a granted app is a catalog
// app, and edit refuses it at load, before any push, so for edit the
// assertion is that nothing is issued or sent.
func TestGrantedPush_EveryIssueFailureSendsNothing(t *testing.T) {
	ca := tlscatest.Controlplane(t, filepath.Join(t.TempDir(), "trust"))
	failures := []relayFailure{failNoResponder, failPrepareRefused, failMalformedKey, failSign, failInstallTransport, failInstallRefused}
	for _, saga := range pushSagas() {
		for _, fail := range failures {
			t.Run(saga.name+"/"+string(fail), func(t *testing.T) {
				nc := apps.StartNATS(t)
				store, inv := saga.seed(t)
				agent := startNodeAgent(t, nc, fail)
				signer := &countingSigner{ca: ca}
				if fail == failSign {
					signer.err = errors.New("sign broke")
				}
				run := saga.run(t, store, inv, nc, relayIdentity(t, nc, inv, signer, "uptime-kuma"))
				if run.Err == nil {
					t.Fatal("the push went ahead although the issue failed")
				}
				if err := nc.Flush(); err != nil {
					t.Fatal(err)
				}
				if n := agent.deploys(); n != 0 {
					t.Errorf("%d deploy commands were published", n)
				}
				if saga.name == "edit" {
					if !errors.Is(run.Err, apps.ErrEditCatalogApp) || slices.Contains(agent.seen(), "prepare") {
						t.Errorf("edit of a granted (catalog) app: err %v, agent saw %v; want ErrEditCatalogApp and nothing issued", run.Err, agent.seen())
					}
					return
				}
				if run.FailedAt != "push" || !strings.Contains(run.Err.Error(), apps.TestAppID) {
					t.Errorf("failed at %s with %v; want the push, naming the app", run.FailedAt, run.Err)
				}
				if fail == failNoResponder && !strings.Contains(run.Err.Error(), "update the node") {
					t.Errorf("an agent below the app.relay floor: %v; want it told to update the node", run.Err)
				}
				if saga.name == "deploy" {
					if row, _ := store.Get(context.Background(), apps.TestAppID); row.LastStatus == proto.AppStatusDeploying {
						t.Error("a refused deploy was marked DEPLOYING")
					}
				}
				der := base64.StdEncoding.EncodeToString(agent.der)
				texts := append(slices.Clone(run.Logs), run.Err.Error())
				for _, r := range run.Results {
					texts = append(texts, string(r))
				}
				for _, s := range texts {
					if strings.Contains(s, "BEGIN") || strings.Contains(s, der) {
						t.Errorf("key or certificate bytes reached the job: %s", s)
					}
				}
			})
		}
	}
}
