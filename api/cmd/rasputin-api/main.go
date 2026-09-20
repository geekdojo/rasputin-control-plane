package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog/floor"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/ids"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sdnotify"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// rasputin-api: the Rasputin control-plane backend.
//
// Architecture: projects/rasputin/design/control-plane/architecture.md
//   in the geekdojo-brain.

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	dataDir := envOr("RASPUTIN_DATA_DIR", "./data")
	httpAddr := envOr("RASPUTIN_HTTP_ADDR", ":8080")
	// Native HTTPS for first-run WebAuthn bootstrap: browsers only run the
	// passkey ceremony in a secure context with a domain-name RP ID, so an
	// appliance reached as https://<cluster-id>.local must terminate TLS
	// itself. Empty (the default) keeps dev behavior exactly as before — plain
	// HTTP only. The OS image's systemd unit sets :443 (plus
	// RASPUTIN_HTTP_ADDR=:80). It deliberately does NOT set RASPUTIN_RP_ID,
	// RASPUTIN_RP_ORIGINS or RASPUTIN_PUBLIC_BASE_URL: those derive from
	// RASPUTIN_CLUSTER_ID as <cluster-id>.local (ADR-0003; see applianceOr).
	httpsAddr := os.Getenv("RASPUTIN_HTTPS_ADDR")
	// obsIngestAddr is the dedicated mTLS remote-write ingress for per-node obs
	// collectors (Slice 1.2b, observability-stack.md §3.10). It comes up only in
	// appliance mode (HTTPS on) — dev has no mesh server leaf and no compute
	// nodes — and defaults to :8443 on all interfaces so compute/storage nodes
	// can reach it via rasputin.local, the same mDNS path they already use for
	// NATS. mTLS-only (RequireAndVerifyClientCert against the mesh CA): a
	// connection without a mesh-CA-signed client cert never completes the
	// handshake, so an always-open :8443 is not an open door, and VM stays
	// loopback-only behind it.
	obsIngestAddr := ""
	if httpsAddr != "" {
		obsIngestAddr = envOr("RASPUTIN_OBS_INGEST_ADDR", ":8443")
	}

	// The JetStream store holds the job ledger: owner-only, existing installs
	// included. The data dir itself is shared with the agent and the OS
	// (/var/lib/rasputin) and keeps its mode.
	if err := atrest.EnsureSecretDir(filepath.Join(dataDir, "nats")); err != nil {
		log.Fatalf("rasputin-api: data dir: %v", err)
	}
	dbPath := filepath.Join(dataDir, "rasputin.db")

	// Restore-before-first-boot (design/storage.md §4.5, #291): if the
	// previous process prepared a restore, swap the restored identity set into
	// place NOW — before the bus, before the first OpenStore, before the mesh
	// CA is loaded — so everything below boots onto it exactly as it would on
	// any other start. Fatal on failure: a partition holding a prepared
	// restore that could not be applied must not come up as a fresh cluster
	// and offer first-run setup over the top of it. The trust and mesh dirs
	// are resolved here from the same env the sections below read, so the
	// files land where those sections will look.
	restoreLayout := storage.RestoreLayout{
		DataDir:      dataDir,
		TrustDir:     envOr("RASPUTIN_TRUST_DIR", filepath.Join(dataDir, "trust")),
		MeshStateDir: envOr("RASPUTIN_MESH_STATE_DIR", filepath.Join(dataDir, "mesh")),
		BusDir:       filepath.Join(dataDir, "bus"),
	}
	appliedRestore, restored, restoreErr := storage.ApplyPendingRestore(restoreLayout)
	if restoreErr != nil {
		log.Fatalf("rasputin-api: %v", restoreErr)
	}
	if restored {
		log.Printf("rasputin-api: RESTORED the identity set from backup generation %s (cluster %q, key %s): %d file(s) put back, %d app volume(s) present in the generation and NOT restored (phase 2). Booting onto the restored identity.",
			appliedRestore.GenerationID, appliedRestore.ClusterID, appliedRestore.KeyID, len(appliedRestore.Restored), len(appliedRestore.AppVolumesPresent))
	}
	if n := storage.SweepRestoreStaging(dataDir); n > 0 {
		log.Printf("rasputin-api: swept %d abandoned restore staging director(ies)", n)
	}
	// A prepared restore ends this process so the unit can start a new one
	// onto the restored files. The exit is NON-ZERO on purpose: it restarts
	// under Restart=on-failure as well as Restart=always, and it is the
	// first deferred call registered so it runs last, after every store
	// below has closed. See restoreExit.
	defer restoreExit()

	// NATS bind defaults to 127.0.0.1:4222 (api-local agents only). Operators
	// federating agents from other nodes set RASPUTIN_NATS_HOST=0.0.0.0
	// (or a specific LAN IP) so the embedded server is reachable. Port
	// override is rarely useful but kept symmetric.
	natsHost := envOr("RASPUTIN_NATS_HOST", "127.0.0.1")
	natsPort := 4222
	if p, err := strconv.Atoi(envOr("RASPUTIN_NATS_PORT", "4222")); err == nil && p > 0 {
		natsPort = p
	}

	// Bus auth (RASPUTIN_BUS_AUTH=off|enforce). Under enforcement, external
	// agents must present a per-node join token that the in-process busauth
	// responder validates → mints a subject-scoped JWT; the api's own connection
	// authenticates as an AuthUser and bypasses the callout. See architecture §5.4.
	//
	// FAIL-CLOSED DEFAULT: enforce unless explicitly disabled with `=off`. Every
	// node is onboarded with a bound join token (firstboot fails loud without one)
	// and the controlplane preloads the matching hashes, so enforcement is the
	// safe default — a matched set has always shipped enforced (rasputin-provision
	// bakes `=enforce`). The old `off` default was fail-OPEN: a hand-written or
	// incomplete CP seed that omitted the setting silently degraded to an open bus
	// with no signal (bit rasputin-local 2026-07-12 — an OTA-test hand-seed left 24
	// nodes on an unauthenticated bus). Now the only way to an open bus is a
	// deliberate, visible `=off` (surfaced by the bus-auth-off alert). DEPLOY NOTE:
	// a cluster already running open should verify token-readiness (dry-run
	// reconciliation: every live node's token hashes to an active bound record)
	// before updating to a build carrying this default, or set `=off` explicitly.
	busAuthEnforce := envOr("RASPUTIN_BUS_AUTH", "enforce") != "off"
	busCfg := bus.Config{Host: natsHost, Port: natsPort, StoreDir: filepath.Join(dataDir, "nats")}
	var (
		busIssuer *busauth.Issuer
		err       error
	)
	if busAuthEnforce {
		busIssuer, err = busauth.EnsureIssuer(filepath.Join(dataDir, "bus"))
		if err != nil {
			log.Fatalf("rasputin-api: bus auth issuer: %v", err)
		}
		apiPass, err := randomSecret()
		if err != nil {
			log.Fatalf("rasputin-api: bus auth secret: %v", err)
		}
		busCfg.AuthEnforce = true
		busCfg.IssuerPublicKey = busIssuer.PublicKey()
		busCfg.APIUser = "rasputin-api"
		busCfg.APIPass = apiPass
		log.Printf("rasputin-api: bus auth ENFORCED (issuer=%s)", busIssuer.PublicKey())
	} else {
		log.Printf("rasputin-api: bus auth OFF (explicitly disabled via RASPUTIN_BUS_AUTH=off — the bus accepts any connection; unset it to fail closed)")
	}

	// Bus TLS (geekdojo/geekdojo-brain#448): the dedicated bus key — the
	// provisioned one firstboot wrote to <dataDir>/bus/bus.key, or one
	// generated now — served as server-auth TLS that nodes trust by pin. The
	// mode (offer | migrate | require, bustls.Mode) decides whether plaintext
	// is still accepted. It is read before the server starts so a controlplane
	// already in require starts refusing plaintext; the move to require while
	// running replaces the server in-process (bustls.Service, below).
	//
	// A key that will not load is survived, not fatal: the bus comes up
	// plaintext-only and says why, because a controlplane that will not start
	// cannot be used to fix anything (#89). Pinned nodes refuse plaintext, so
	// nothing of theirs crosses the wire while it is broken.
	busKey, busKeyGenerated, busKeyErr := bustls.EnsureKey(filepath.Join(dataDir, "bus"))
	var serverTLS *tls.Config
	if busKeyErr != nil {
		log.Printf("rasputin-api: ⚠️  bus TLS OFF — %v. The bus accepts PLAINTEXT ONLY; every node that holds a bus pin stays off it until the key file is fixed or restored.", busKeyErr)
		busKey = nil
	} else {
		// The PERSISTED certificate around the key (geekdojo/geekdojo-brain
		// #508), not a fresh one per start: it carries a fixed DNS SAN, and
		// its exact bytes are what a client that verifies the name — the
		// collector, the node listener — will pin. EnsureCert returns a usable
		// certificate even when it had to replace the file, so an error here
		// is a note, not a reason to drop TLS. Only a failure to produce one
		// at all leaves it zero-valued.
		busCert, busCertGenerated, certErr := bustls.EnsureCert(filepath.Join(dataDir, "bus"), busKey)
		if len(busCert.Certificate) == 0 {
			log.Printf("rasputin-api: ⚠️  bus TLS OFF — %v. The bus accepts PLAINTEXT ONLY.", certErr)
			busKey = nil
		} else {
			switch {
			case certErr != nil:
				log.Printf("rasputin-api: bus certificate re-minted: %v", certErr)
			case busCertGenerated:
				log.Printf("rasputin-api: bus certificate minted and persisted to %q (DNS %q)", filepath.Join(dataDir, "bus", bustls.CertFileName), bustls.BusDNSName)
			}
			serverTLS = bustls.ServerTLSConfigFor(busCert)
		}
	}
	// The mode is resolved AFTER the key, because whether this api can serve
	// TLS at all is one of the facts it resolves on (bustls.StartFacts).
	busTLSStart := busTLSStartMode(ctx, dbPath, busKey != nil)
	busTLSMode, busTLSModePinned := busTLSStart.Mode, busTLSStart.Pinned
	if busTLSStart.Fault != "" {
		log.Printf("rasputin-api: ⚠️  bus TLS mode: %s — running as %q instead (%s); this is re-derived on every start until the recorded value is fixed",
			busTLSStart.Fault, busTLSMode, busTLSStart.Why)
	}
	if busTLSStart.Derived {
		// Persisted so the next start reads it back: a fresh cluster that
		// derived require from "no node is enrolled" must not fall back to
		// offer the moment its own agent has registered and that fact is
		// no longer true. A failure to record it is survivable — the same
		// facts derive the same mode next time — so it is logged, not fatal.
		if perr := recordBusTLSMode(ctx, dbPath, busTLSMode); perr != nil {
			log.Printf("rasputin-api: bus TLS mode %q was derived (%s) but could not be recorded: %v", busTLSMode, busTLSStart.Why, perr)
		} else {
			log.Printf("rasputin-api: bus TLS mode %q recorded: %s", busTLSMode, busTLSStart.Why)
		}
	}
	if serverTLS != nil {
		busCfg.TLS = serverTLS
		busCfg.AllowNonTLS = busTLSMode.AllowsPlaintext()
		origin := "loaded"
		if busKeyGenerated {
			origin = "GENERATED (no provisioned key) — nodes seeded with a different pin cannot join; restore the identity backup if this controlplane was reflashed"
		}
		log.Printf("rasputin-api: bus TLS on, mode=%s (pinned=%t, plaintext %s), bus key %s, pin %s",
			busTLSMode, busTLSModePinned, map[bool]string{true: "allowed", false: "REFUSED"}[busTLSMode.AllowsPlaintext()], origin, busKey.Pin())
		// The pin, beside the token, for this controlplane's own agent. See
		// bustls.WriteAgentPinFile: a self-initialised controlplane has no
		// seed, and one that starts in require can never deliver a pin over
		// the bus. Survivable: an agent that was seeded a pin does not need
		// the file, so this is logged rather than fatal (#89).
		if pinPath, perr := bustls.WriteAgentPinFile(filepath.Join(dataDir, "bus"), busKey); perr != nil {
			log.Printf("rasputin-api: ⚠️  could not write the bus pin for this controlplane's agent at %q: %v — an agent with no seeded pin of its own cannot join a bus that requires TLS", pinPath, perr)
		} else {
			log.Printf("rasputin-api: bus pin for this controlplane's agent written to %q", pinPath)
		}
	}

	busSrv, err := bus.Start(ctx, busCfg)
	if err != nil {
		log.Fatalf("rasputin-api: bus: %v", err)
	}
	defer busSrv.Stop()
	log.Printf("rasputin-api: nats listening on %s", busSrv.ClientURL())

	// Token store backs both the auth-callout responder and the token-mgmt
	// endpoints. Opened regardless of enforcement so an operator can mint
	// tokens BEFORE flipping enforce on.
	busTokenStore, err := busauth.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: bus token store: %v", err)
	}
	defer busTokenStore.Close()

	// Preload any provisioning matched-set tokens (hashes + node bindings) the
	// controlplane shipped with — firstboot drops the file on the persistent
	// partition (token-provisioning-pipeline.md §4c). Idempotent, so it's safe on
	// every boot; done regardless of enforcement so the tokens are known before a
	// later flip to enforce. A bad/missing file never blocks boot — a node that
	// can't join is a better failure than a controlplane that won't start. A file
	// binding a token to an invalid node id is refused whole (nothing loads) and
	// the error names the entry; see busauth.Store.PreloadHashes.
	//
	// Revocation tombstones first: see loadBusTokenState.
	loadBusTokenState(ctx, busTokenStore, dataDir)
	logUnboundBusTokens(ctx, busTokenStore)
	logRolelessBusTokens(ctx, busTokenStore)

	// The api's own node id — the system.update saga skips this one (the
	// operator updates the controlplane node manually after the cascade), and
	// it is the id the controlplane's own agent authenticates to the bus as.
	selfNodeID := os.Getenv("RASPUTIN_SELF_NODE_ID")

	// The controlplane's own agent authenticates with a join token like every
	// other node; the bus trusts nothing for coming from loopback
	// (geekdojo/geekdojo-brain#140). Mint it here, before the responder admits
	// anyone and long before READY=1, so the agent — ordered After= this unit —
	// finds the file on its first connect. Zero-touch: nobody provisions it.
	ensureSelfAgentToken(ctx, busTokenStore, filepath.Join(dataDir, "bus", proto.BusAgentTokenFileName), selfNodeID)

	// The node registry (inventory.Registry) is the api's one in-memory node
	// list: membership and last-seen loaded from the nodes table by OpenStore,
	// token liveness pushed in by the token store below. EVERY node membership
	// and liveness decision the api makes reads it — the bus auth callout per
	// connection, the collector ingress per handshake, heartbeats,
	// registration, the collector reconcile and the mesh converge steps — so
	// none of them touches the database (geekdojo/geekdojo-brain#585).
	//
	// It is opened and loaded BEFORE the auth-callout responder starts, because
	// an unloaded registry admits nobody: a node connecting first would be
	// refused rather than served from a database read.
	invStore, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: inventory store: %v", err)
	}
	defer invStore.Close()
	// A failure here leaves every node holding no live token in the registry,
	// so node-facing admission refuses everyone: fail closed, and say so.
	if err := busTokenStore.SetNodeRegistry(ctx, invStore.Registry()); err != nil {
		log.Printf("rasputin-api: ⚠️  node registry: token liveness did not load: %v — the bus and the collector ingress admit no node until the api restarts cleanly", err)
	}
	// One fact, one cascade: a node stops being admitted when its last live
	// token is revoked or it is removed from inventory, and that fact closes
	// its bus sessions, closes its collector-ingress connections and ends its
	// contested-token alert (geekdojo/geekdojo-brain#500, #585). No timer, and
	// no second node-keyed cache beside the registry.
	invStore.Registry().OnNodeExcluded(func(nodeID string) {
		if busTokenStore.DisconnectNode(nodeID) > 0 {
			log.Printf("rasputin-api: node %q is no longer admitted (removed, or its last join token revoked) — its live bus session(s) are closed", nodeID)
		}
	})
	invStore.Registry().OnNodeExcluded(busTokenStore.ForgetNode)

	// The bus TLS service, once it exists (it is built further down, after the
	// stores it reads). The responder reads it from the first callout on, so
	// it is handed over atomically.
	var busTLSForHold atomic.Pointer[bustls.Service]
	if busAuthEnforce {
		// Before the responder starts, so every connection it admits is
		// recorded and a revoke can close it (certificates.md §4.2(1)).
		busTokenStore.TrackSessions(busSrv)
		responder := busauth.NewResponder(busSrv.Conn(), busIssuer, busTokenStore)
		// While the bus server is being replaced to refuse plaintext, admit
		// no node: job intake reopens only after the api's own connection is
		// back, and a node registering before that could have a registration
		// hook's job refused with nobody to retry it. Held nodes retry on
		// their own reconnect loop.
		responder.SetHold(func() (bool, string) {
			if svc := busTLSForHold.Load(); svc != nil {
				return svc.Switching()
			}
			return false, ""
		})
		if err := responder.Start(); err != nil {
			log.Fatalf("rasputin-api: bus auth responder: %v", err)
		}
		defer responder.Stop()
	}

	jobStore, err := jobs.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: jobs store: %v", err)
	}
	defer jobStore.Close()

	authStore, err := auth.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: auth store: %v", err)
	}
	defer authStore.Close()

	fwStore, err := firewall.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: firewall store: %v", err)
	}
	defer fwStore.Close()

	metricsStore, err := metrics.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: metrics store: %v", err)
	}
	defer metricsStore.Close()

	appsStore, err := apps.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: apps store: %v", err)
	}
	defer appsStore.Close()

	updaterStore, err := updater.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: updater store: %v", err)
	}
	defer updaterStore.Close()

	meshStore, err := mesh.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: mesh store: %v", err)
	}
	defer meshStore.Close()
	// Device→node bindings come only from enrols. Keep those the job ledger
	// proves, clear the rest (their nodes re-enrol on the next reconcile),
	// and make a second binding for one node impossible.
	if _, err := mesh.VerifyBindings(ctx, meshStore, mesh.JobsLedger{Store: jobStore}); err != nil {
		log.Printf("rasputin-api: ⚠️  verify mesh device bindings: %v", err)
	}

	bmcStore, err := bmc.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: bmc store: %v", err)
	}
	defer bmcStore.Close()

	setupStore, err := setup.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: setup store: %v", err)
	}
	defer setupStore.Close()

	// backup_targets — design/storage.md §4.8's ledger of claimed backup disks.
	backupStore, err := storage.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: storage store: %v", err)
	}
	defer backupStore.Close()
	// The record of a restore this start applied goes into the database it
	// restored — the one just opened. Idempotent; nothing to do on an
	// ordinary start.
	if rep, err := storage.RecordAppliedRestore(ctx, backupStore, dataDir); err != nil {
		log.Printf("rasputin-api: record applied restore: %v", err)
	} else if rep != nil {
		log.Printf("rasputin-api: restore %s from generation %s recorded in the restored database", rep.ID, rep.GenerationID)
	}

	// Trust material lives at <trustDir>/. Used by:
	//   - updater.Verifier (root-ca.pem; bundle signatures)
	//   - mesh.EnsureMeshCA (mesh-ca.{key,pem}; per-installation TLS CA)
	//   - the .mobileconfig endpoint (serves mesh-ca.pem to operator devices)
	// Set up ahead of mesh because the docker supervisor needs the Mesh CA
	// at construction time. See wiki design/control-plane/certificates.md.
	trustDir := envOr("RASPUTIN_TRUST_DIR", filepath.Join(dataDir, "trust"))
	// Owner-only: it holds the Mesh CA key (EnsureMeshCA tightens it too).
	if err := atrest.EnsureSecretDir(trustDir); err != nil {
		log.Fatalf("rasputin-api: trust dir: %v", err)
	}

	// Mesh subsystem. The controlplane self-hosts Headscale: when Docker is
	// present (production and most dev), the api brings up the Headscale
	// container, mints its own admin API key against it, and talks to it for
	// real — no operator input, no provision-time secret. Only when there's
	// no Docker daemon AND no external Headscale configured does it fall back
	// to the file-backed mock (CI, bare dev). Override the autodetect with
	// RASPUTIN_MESH_BACKEND=mock|headscale|auto (default auto); point at an
	// externally-managed Headscale with RASPUTIN_HEADSCALE_URL +
	// RASPUTIN_HEADSCALE_API_KEY. See wiki design/control-plane/mesh.md §2.
	meshStateDir := envOr("RASPUTIN_MESH_STATE_DIR", filepath.Join(dataDir, "mesh"))
	// Owner-only: it holds Headscale's state (its database, noise key and
	// leaf key) and, with the mock, pre-auth keys.
	if err := atrest.EnsureSecretDir(meshStateDir); err != nil {
		log.Fatalf("rasputin-api: mesh state dir: %v", err)
	}
	installName := envOr("RASPUTIN_INSTALL_NAME", "rasputin")
	// One clock gate for every certificate this process dates. The HTTPS
	// leaf's mint used to be the only thing that waited for NTP; handing the
	// gate to the Mesh CA puts every leaf minted under it — Headscale's, each
	// node's collector leaf, each app's leaf — behind the same check, so none
	// of them can be anchored in a bogus pre-NTP window and read as expired
	// once the clock corrects. It waits at most once; see trustedClock.
	clockGate := newTrustedClock(ctx, clockGateTimeout)
	meshCA, err := mesh.EnsureMeshCA(trustDir, installName, mesh.WithLeafClockGate(clockGate.ok))
	if err != nil {
		log.Fatalf("rasputin-api: mesh CA: %v", err)
	}
	log.Printf("rasputin-api: mesh CA loaded (CN=%s, expires=%s)",
		meshCA.Cert.Subject.CommonName, meshCA.Cert.NotAfter.Format("2006-01-02"))
	// One renewal driver for every Mesh-CA leaf this controlplane holds
	// (§7.1). Consumers register below as they are built; the sweep itself is
	// a job on the schedule, and what it does is decided by each leaf's
	// NotAfter, not by the tick.
	leafSweeper := mesh.NewLeafSweeper(meshCA)
	defaultLogin := envOr("RASPUTIN_MESH_LOGIN_SERVER", "https://mesh.rasputin.local")
	mw, err := wireMesh(meshStateDir, meshCA, defaultLogin)
	if err != nil {
		log.Fatalf("rasputin-api: mesh: %v", err)
	}
	// Headscale serves a Mesh-CA leaf and reads it only at container start, so
	// its renewal needs a restart to reach a client. Registered only for the
	// self-hosted Docker backend: the mock has no container, and an external
	// Headscale brings its own certificate.
	if sup, ok := mw.sup.(*mesh.DockerSupervisor); ok && sup != nil {
		if err := leafSweeper.Register(sup.LeafConsumer()); err != nil {
			log.Fatalf("rasputin-api: leaf sweep: %v", err)
		}
	}
	// The scheduler's mesh.reconcile cadence (also read where the scheduler
	// is built). The mesh service needs it too: the staleness bound on "on
	// the mesh" is three of these (mesh.Service.MembershipMaxAge), so the
	// two must agree.
	meshReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_MESH_RECONCILE_INTERVAL"), 5*time.Minute)
	meshSvc := mesh.NewService(mesh.Config{
		LoginServer:       mw.login,
		DefaultUser:       envOr("RASPUTIN_MESH_DEFAULT_USER", "rasputin-operator"),
		HeadplaneURL:      os.Getenv("RASPUTIN_HEADPLANE_URL"),
		ReconcileInterval: meshReconcileEvery,
		MeshCAPEM:         mw.caPEM,
		ClusterID:         strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
	}, meshStore, mw.client, mw.sup)
	// The node↔mesh-device join (geekdojo/geekdojo-brain#401): every reader
	// of a node's status — /api/nodes, the transition ticker, the alerts
	// aggregator, ExplainNoResponder — derives OFF BUS from this one lookup.
	invStore.SetMeshLookup(meshSvc.Membership)
	if mw.bootstrap != nil {
		meshSvc.SetBootstrap(mw.bootstrap)
	}
	// Feed the tailnet app-name DNS projection (ADR-0004 §9): each app resolves at
	// <app>.<cluster-id>.internal → its target node's tailnet IP via Headscale
	// extra_records. Read live per reconcile (store error → project nothing).
	meshSvc.SetAppLister(func() []mesh.AppDNS {
		list, err := appsStore.List(ctx)
		if err != nil {
			log.Printf("rasputin-api: mesh app-DNS projection: %v", err)
			return nil
		}
		out := make([]mesh.AppDNS, 0, len(list))
		for _, a := range list {
			out = append(out, mesh.AppDNS{Name: a.Name, TargetNode: a.TargetNode})
		}
		return out
	})
	// Start is non-blocking: mesh bring-up runs in the background so a slow or
	// failing Headscale never delays /healthz or kills the api.
	_ = meshSvc.Start(ctx)
	defer meshSvc.Stop()

	// Bundles live on disk; the api streams them to agents. The
	// bundle-signing root-ca.pem lives at <trustDir>/root-ca.pem and is
	// owned by Rasputin Inc. (separate CA from the Mesh TLS CA above —
	// see certificates.md for why).
	bundleDir := envOr("RASPUTIN_BUNDLE_DIR", filepath.Join(dataDir, "bundles"))
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: bundle dir: %v", err)
	}
	verifier := wireBundleVerifier(trustDir)
	// Public URL the agent uses to fetch bundles. In dev the api is at
	// :8080; in production this is the api's tailnet hostname.
	publicBaseURL := envOr("RASPUTIN_PUBLIC_BASE_URL", applianceOr(
		func(h string) string { return "https://" + h }, "http://localhost:8080"))
	// The control plane's own LAN IPv4, followed from kernel address events
	// rather than looked up once at start (geekdojo/geekdojo-brain#431). Every
	// consumer below — the nameserver's listeners and self answers, the
	// firewall's DNS forward, this node's inventory row, the HTTPS leaf's IP
	// SAN — reads it from here or subscribes to its changes. Started this early
	// so the address is known before anything that reports it is wired.
	lanWatch := lanaddr.NewWatcher(lanaddr.SystemSource())
	if err := lanWatch.Start(ctx); err != nil {
		log.Printf("rasputin-api: LAN address changes will not be followed (%v); using the start-time address: %s", err, lanWatch.Snapshot())
	}
	// The BMC host's node id lives in settings (bmc.host_node_id,
	// bmc-settings.md S-5) and is read live so a Settings change
	// redirects routing without a restart. The env var seeds first boot
	// only (seedObsEnabled recipe); the operator's choice wins after.
	seedBMCHostNode(ctx, setupStore, envOr("RASPUTIN_BMC_HOST_NODE_ID", selfNodeID))
	bmcSvc := bmc.NewService(bmc.Config{HostFn: func(ctx context.Context) string {
		v, err := setupStore.Get(ctx, setup.KeyBMCHostNode)
		if err != nil {
			log.Printf("bmc: read %s: %v", setup.KeyBMCHostNode, err)
			return ""
		}
		return v
	}}, bmcStore, busSrv.Conn())

	// Setup wizard service. Probes are functions over the other
	// subsystems' stores; defined here so the setup package stays narrow
	// and import-cycle-free.
	setupSvc := setup.NewService(setupStore, setup.Probes{
		// auth's FirstRun, the one first-run predicate. The store form is
		// used only because the auth Service is built further down.
		HasUsers: func(ctx context.Context) (bool, error) {
			firstRun, err := authStore.FirstRun(ctx)
			if err != nil {
				return false, err
			}
			return !firstRun, nil
		},
		TrustConfigured: func() bool { return verifier.TrustConfigured() },
		MeshEnrolled: func(ctx context.Context, selfNodeID string) (bool, error) {
			devices, err := meshStore.ListDevices(ctx)
			if err != nil {
				return false, err
			}
			for _, d := range devices {
				if d.RasputinNodeID == selfNodeID && d.Kind == "rasputin" {
					return true, nil
				}
			}
			return false, nil
		},
		HasFirewallNode: func(ctx context.Context) (bool, error) {
			nodes, err := invStore.ListByRole(ctx, proto.RoleFirewall)
			if err != nil {
				return false, err
			}
			return len(nodes) > 0, nil
		},
	}, selfNodeID, clusterHostname(), strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")))

	// Capture the operator's SSH key as a cluster setting on first sight:
	// the first key line of the control plane's own authorized_keys is the
	// bootstrap seed's key, so a fresh cluster prefills the Add-node wizard
	// before it's ever opened. Only fires while the setting has NEVER been set
	// (an operator's explicit clear sticks); best-effort — a missing
	// or unreadable file must never block boot (dev api has no seed).
	akPath := envOr("RASPUTIN_CP_AUTHORIZED_KEYS", "/var/lib/rasputin/dropbear/authorized_keys")
	if key, others, err := setupSvc.SeedOperatorSSHKeyFromFile(ctx, akPath); err != nil {
		log.Printf("setup: seed operator SSH key from %s: %v (continuing)", akPath, err)
	} else if key != "" {
		log.Printf("setup: captured operator SSH key from %s (first of %d key line(s); the setting holds one)", akPath, others+1)
	}

	// Default origins cover both ways the UI reaches the api on localhost:
	// the Next dev server (:3000, cross-origin) and the api-served static
	// export (:8080, same-origin — including `ssh -L 8080:localhost:8080`
	// tunnels, still a valid escape hatch). On a real appliance the defaults
	// derive from RASPUTIN_CLUSTER_ID instead — RP ID <cluster-id>.local and
	// origin https://<cluster-id>.local (ADR-0003) — and the OS image enables
	// the native HTTPS listener (RASPUTIN_HTTPS_ADDR above) so the passkey
	// ceremony gets its secure context without any tunnel.
	authCfg := auth.Config{
		RPDisplayName: envOr("RASPUTIN_RP_NAME", "Rasputin"),
		RPID:          envOr("RASPUTIN_RP_ID", applianceOr(func(h string) string { return h }, "localhost")),
		RPOrigins: splitCSV(envOr("RASPUTIN_RP_ORIGINS", applianceOr(
			func(h string) string { return "https://" + h },
			"http://localhost:3000,http://localhost:8080"))),
		SecureCookies: secureCookies(httpsAddr, envBoolPtr("RASPUTIN_SECURE_COOKIES")),
	}
	// Say what this node believes its identity IS, on startup, verbatim.
	//
	// These four values are DERIVED from RASPUTIN_CLUSTER_ID now (ADR-0003), and
	// until this line they appeared in no log, no endpoint and no health check —
	// so a wrong derivation surfaced only when an operator's passkey silently
	// failed to work. WebAuthn binds credentials to the RP ID, which makes this
	// the least forgiving value on the box to get wrong quietly.
	//
	// It is also the only channel CI can see: the QEMU boot smoke has no shell
	// into the guest and asserts by grepping the serial console. A value that
	// never reaches the console is a value no build can ever check — the exact
	// gap that let a truncated RASPUTIN_MDNS_RECOVER_CMD ship for a whole
	// release past green CI (rasputin-os #23).
	log.Printf("rasputin-api: cluster identity: rp-id=%q origins=%q public-base-url=%q (cluster-id=%q)",
		authCfg.RPID, strings.Join(authCfg.RPOrigins, ","), publicBaseURL,
		envOr("RASPUTIN_CLUSTER_ID", "<unset — dev defaults>"))
	// A provisioned appliance (self-node id set) that still derived a loopback
	// public-base-url is misconfigured: nodes cannot fetch update bundles from
	// here, and node.update will be refused (see updater.remoteLoopbackBundleURL).
	// This is the RASPUTIN_CLUSTER_ID-unset trap on a cluster whose node.env
	// predates per-cluster naming — the rasputin-os backfill migration fixes it
	// going forward; warn loudly (and greppably, for CI) if we hit it. #75.
	if selfNodeID != "" && updater.IsLoopbackURL(publicBaseURL) {
		log.Printf("rasputin-api: WARNING — public-base-url is loopback (%q) on a provisioned appliance (self-node %s); nodes cannot fetch update bundles and node.update will be refused. Set RASPUTIN_CLUSTER_ID (default %q) in /var/lib/rasputin/node.env and restart. See control-plane #75.",
			publicBaseURL, selfNodeID, "rasputin")
	}

	authSvc, err := auth.NewService(authStore, authCfg)
	if err != nil {
		log.Fatalf("rasputin-api: auth service: %v", err)
	}
	// On every successful login (and first-credential registration), ensure
	// a matching Headscale user exists. EnsureUser is idempotent + cached,
	// so this costs at most one HTTP round-trip on cold start per user;
	// the mock backend turns it into a single map write. Errors are logged
	// inside runLoginHook and never block the login response — auth stays
	// usable when mesh/Headscale are unhealthy.
	// Use meshSvc.Client() (not a captured client) so this picks up the real
	// Headscale client once the self-hosted bring-up swaps it in; before that
	// it returns ErrMeshNotReady, which the hook logs and ignores.
	authSvc.SetLoginHook(func(ctx context.Context, u *auth.User) error {
		return meshSvc.Client().EnsureUser(ctx, u.Name)
	})
	authSvc.Start(ctx)
	defer authSvc.Stop()

	runner := jobs.NewRunner(jobStore, busSrv.Conn())
	runner.Register(jobs.PingWorkflow())
	runner.Register(jobs.RebootWorkflow())
	// Firewall is managed in every mode except LAN-peer, where the existing
	// router firewalls and our box (if any) is idle. Unset mode (pre-wizard)
	// defaults to managed so a mid-setup box still reconciles.
	fwManaged := func(ctx context.Context) (bool, error) {
		m, err := setupStore.Get(ctx, setup.KeyMode)
		if err != nil {
			return false, err
		}
		return setup.Mode(m) != setup.ModeLANPeer, nil
	}
	runner.Register(firewall.ApplyWorkflow(fwStore, invStore, busSrv.Conn(), fwManaged))
	runner.Register(firewall.ReconcileWorkflow(fwStore, invStore, busSrv.Conn(), fwManaged))
	runner.Register(firewall.SetActiveWorkflow(invStore, busSrv.Conn()))
	// AA-11 Mode-A/C zero-touch DNS (ADR-0004 §10): keep the firewall's dnsmasq
	// conditional-forward for <cluster-id>.internal pointed at the control plane's
	// current LAN IP, auto-applying when it moves. Gated to firewall-present modes
	// by fwManaged; a dev box with no cluster id emits no forward. Submitted on
	// facts only — a LAN address change, the firewall agent registering, a mode
	// change, an edit to the forward — never on a timer (#431); see
	// submitDNSForward below and the api's setup/intent handlers.
	runner.Register(firewall.DNSForwardWorkflow(fwStore, runner, firewall.DNSForwardConfig{
		Zone: func() string {
			if id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")); id != "" {
				return id + ".internal"
			}
			return ""
		},
		Target: func() string {
			return ipString(lanWatch.PrimaryIP())
		},
		Managed: fwManaged,
		Inv:     invStore,
	}))
	submitDNSForward := func(reason string) {
		if _, err := runner.Submit(ctx, "firewall.dns_forward", json.RawMessage(`{}`), reason); err != nil {
			log.Printf("rasputin-api: dns_forward submit (%s): %v", reason, err)
		}
	}
	// Per-app TLS-leaf minter for the deploy saga (ADR-0004 §6): mints a Mesh-CA
	// leaf for the app's FQDN(s) and fills the delivery command. nil (no CA)
	// disables leaf delivery; the app still deploys, just without the proxy.
	var (
		mintAppLeaf   apps.LeafMinter
		rotateAppLeaf apps.LeafRotator
		removeAppLeaf apps.LeafRemover
	)
	if meshCA != nil {
		clusterID := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID"))
		appLeafDir := filepath.Join(dataDir, "tls", "apps")
		// buildAppLeafCmd fills the delivery command from freshly-minted PEMs —
		// shared by the deploy minter and the rotation path so the wire shape
		// (FQDNs, upstream port) can't drift between them.
		//
		// The cert and the route come from different places on purpose. The leaf
		// carries BOTH of the app's names whatever its exposure (a cert is an
		// identity, not an access control), so the route hosts — and only they —
		// decide what the node's proxy will answer for. AppRouteHosts leaves
		// LANFQDN empty for a tailnet-only app, and RenderCaddyConfig drops any
		// app with no LAN host from the LAN listener.
		buildAppLeafCmd := func(app *apps.App, certPEM, keyPEM []byte) proto.AppLeafCmd {
			tailnetFQDN, lanFQDN := mesh.AppRouteHosts(clusterID, app.Name, app.ExposeLAN)
			return proto.AppLeafCmd{
				AppID:        app.ID,
				Name:         app.Name,
				CertPEM:      certPEM,
				KeyPEM:       keyPEM,
				TailnetFQDN:  tailnetFQDN,
				LANFQDN:      lanFQDN,
				UpstreamPort: app.PublishedPort,
				UpstreamTLS:  app.WebTLS,
			}
		}
		mintAppLeaf = func(app *apps.App) (proto.AppLeafCmd, error) {
			certPEM, keyPEM, err := mesh.MintAppLeaf(meshCA, clusterID, app.Name)
			if err != nil {
				return proto.AppLeafCmd{}, err
			}
			return buildAppLeafCmd(app, certPEM, keyPEM), nil
		}
		// rotateAppLeaf is the disk-backed form used by the rotation sweep and by
		// the exposure toggle. It always returns the app's CURRENT desired state
		// — RotateAppLeaf delivers it either way — and renewed reports only
		// whether the cert in it is new, which is what decides the commit
		// (apps.LeafRotator).
		rotateAppLeaf = func(app *apps.App) (proto.AppLeafCmd, bool, func() error, error) {
			dir := filepath.Join(appLeafDir, app.ID)
			certPEM, keyPEM, renewed, err := mesh.PrepareAppLeaf(meshCA, dir, clusterID, app.Name)
			if err != nil {
				return proto.AppLeafCmd{}, false, nil, err
			}
			commit := func() error { return mesh.CommitAppLeaf(dir, certPEM, keyPEM) }
			return buildAppLeafCmd(app, certPEM, keyPEM), renewed, commit, nil
		}
		removeAppLeaf = func(appID string) error {
			return removeAppLeafDir(appLeafDir, appID)
		}
	}
	runner.Register(apps.DeployWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf))
	runner.Register(apps.StopWorkflow(appsStore, invStore, busSrv.Conn()))
	// app.revert (#411): re-apply an app's previous compose, named by hash. Its
	// compose comes from the row, so unlike app.upgrade it needs nothing from
	// the catalog.
	runner.Register(apps.RevertWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf))
	// app.edit (#410): replace a custom app's compose with one its owner sent.
	// The compose is held in composeStash, never in the job spec; the server
	// is given the same stash below, and the workflow discards what it holds
	// when the job ends.
	composeStash := apps.NewComposeStash()
	runner.Register(apps.EditWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf, composeStash))
	runner.Register(apps.DeleteWorkflow(appsStore, invStore, busSrv.Conn(), removeAppLeaf))
	runner.Register(apps.ReconcileWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf))
	runner.Register(apps.RotateLeavesWorkflow(appsStore, invStore, busSrv.Conn(), rotateAppLeaf))
	runner.Register(updater.UpdateWorkflow(updaterStore, invStore, busSrv.Conn(), updater.Config{
		PublicBaseURL: publicBaseURL,
		SelfNodeID:    selfNodeID,
	}))
	runner.Register(updater.SystemUpdateWorkflow(updaterStore, invStore, jobStore, runner, busSrv.Conn(), updater.SystemUpdateConfig{
		SelfNodeID: selfNodeID,
	}))
	runner.Register(mesh.ApplyWorkflow(meshSvc, invStore, busSrv.Conn()))
	runner.Register(mesh.ReconcileWorkflow(meshSvc, invStore, jobStore, runner, busSrv.Conn()))
	runner.Register(mesh.EnrollNodeWorkflow(meshSvc, invStore, busSrv.Conn()))
	// Per-node collector leaves. A source rather than a fixed registration:
	// the set follows inventory, so a node that has been removed is no longer
	// renewed (§5.2 revocation), and a node that has never had a collector is
	// never minted one here — only directories that already exist are swept.
	// A renewed leaf rides to the node inside its collector compose, so the
	// reload hook is a redeploy.
	leafSweeper.RegisterSource(collectorLeafSource(
		filepath.Join(dataDir, "tls", "collectors"), invStore,
		func(ctx context.Context, nodeID string) error {
			spec, err := json.Marshal(obs.CollectorNodeSpec{NodeID: nodeID})
			if err != nil {
				return err
			}
			_, err = runner.Submit(ctx, obs.CollectorDeployKind, spec, "mesh-leaf-sweep")
			return err
		}))
	// The controlplane's ONE leaf-renewal driver (§7.1). Everything holding a
	// Mesh-CA leaf registers with the sweeper — the api's own HTTPS leaf and
	// Headscale's below, the per-node collector leaves through a source — and
	// the leaf lifecycles that own a delivery contract of their own run as
	// fan-outs from the same job, so there is one thing to look at when a
	// certificate is about to lapse. See mesh/sweep.go.
	runner.Register(mesh.LeafSweepWorkflow(mesh.LeafSweepDeps{
		Sweeper: leafSweeper,
		FanOut: []mesh.LeafFanOut{{
			// The per-app leaves keep their prepare → ship → commit contract
			// (the on-disk copy must not advance past what the node holds),
			// so the sweep submits their sweep rather than re-minting them.
			Name: "apps.leaf_rotate",
			Run: func(sc *jobs.StepCtx) error {
				_, err := runner.Submit(sc.Ctx, "apps.leaf_rotate", nil, "mesh-leaf-sweep")
				return err
			},
		}},
	}))
	// App catalog (ADR-0006). The floor embedded in this build is what a
	// cluster has before it has ever completed a verified fetch; the poller
	// (started further down, once the server exists) replaces it with the
	// newest signed catalog it can verify. Resolution has no third case, so
	// nothing here merges the two.
	//
	// Built HERE, ahead of the backup workflow, because the backup fan-out
	// reads it: this store is the catalog /api/catalog serves, and the
	// fan-out must join installed apps against THAT — not against the tile
	// set embedded in the binary. On e3bench 2026-09-03 the fan-out was wired
	// to catalog.MustLoad(), whose tiles carry no `volumes`, while the store
	// served a verified v17 that classified Vaultwarden's; the run recorded no
	// app volumes and stamped the archive complete.
	//
	// A floor that does not parse is a BUILD defect — every cluster from this
	// image would inherit it — so it is fatal rather than degraded.
	catalogFloor, err := floor.Load()
	if err != nil {
		log.Fatalf("rasputin-api: %v", err)
	}
	catalogStore, err := catalogsync.New(dataDir, catalogsync.NewVerifier(filepath.Join(trustDir, "root-ca.pem")), catalogFloor)
	if err != nil {
		log.Fatalf("rasputin-api: catalog store: %v", err)
	}
	// app.upgrade (#409) registers here rather than with the other app sagas
	// above because its new compose comes from this store and nowhere else.
	runner.Register(apps.UpgradeWorkflow(appsStore, invStore, busSrv.Conn(), mintAppLeaf, catalogStore.GetVersioned))
	// backup.target.claim — the only path in the system that formats a disk
	// (design/storage.md §4.8). The cluster id is stamped into the on-disk
	// marker so a disk can say which cluster wrote it.
	runner.Register(storage.ClaimWorkflow(backupStore, invStore, storage.Config{
		ClusterID: strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
	}))
	// backup.run — design/storage.md §4.1's producer: snapshot the identity
	// set, seal it to the target's PUBLIC key, land it as a generation, prune
	// to four. Registered unconditionally; a cluster with no claimed target
	// gets a clean refusal at step 1 rather than a missing workflow.
	//
	// SCOPE: every generation this build writes is `full` — the database,
	// the mesh CA, Headscale state, AND every `critical`/`state` volume of
	// every installed app on EVERY node, each sealed on the node that hosts
	// it and uploaded to this api's ingest endpoint on a per-member
	// credential (backupxfer, #295/#296). A volume the run could not take is
	// FAILED, named, and fails the run. The saga says so in its own log
	// lines, its manifest, its ledger row and the generation's name on the
	// platter.
	//
	// The ingest endpoint and the workflow share ONE *backupxfer.Ingest: the
	// credentials the fan-out mints are verifiable by exactly the handler
	// that receives them, and by nothing else. The signing key is minted
	// here, per process, from crypto/rand, and lives nowhere else — a run
	// does not survive an api restart, so neither need its credentials.
	//
	// The api does NOT decide where the archive is staged, and nothing here
	// creates a staging directory. The agent on the target node owns that root
	// — it is the containment boundary for the verb that reads it — and reports
	// it in the preflight ack, step 2, before the saga stages anything. The api
	// deriving its own was the 2026-09-02 e3bench failure: it sealed 105 MB into
	// <dataDir>/backup-staging and the agent looked in
	// <stateDir>/backup-staging, on the only configuration that ships.
	//
	// §4.7's third discipline is unchanged, just moved to where the directory
	// is known: the agent sweeps its root at start, and the saga sweeps it again
	// at the top of the snapshot step, before the free-space guard sizes the run.
	backupAuthority, err := backupxfer.NewAuthority()
	if err != nil {
		log.Fatalf("rasputin-api: backup ingest authority: %v", err)
	}
	// RASPUTIN_BACKUP_INGEST_CONCURRENCY is the inbound-upload semaphore —
	// design/storage.md §4.7's backpressure. One by default: the fan-out is
	// serial and the target may be spinning media.
	backupIngest := backupxfer.New(backupAuthority, parseIntOr(os.Getenv("RASPUTIN_BACKUP_INGEST_CONCURRENCY"), backupxfer.DefaultConcurrency))
	// backup.restore_app — design/storage.md §4.5's restore, phase 2 (#291):
	// one app's classified volumes, from one generation, back to the node
	// that hosts the app. The operator's browser lends the archive's private
	// key for one restore; it lives in restoreSessions, in memory, never in
	// a job spec, and dies with the job. The api unseals each member and
	// streams the PLAINTEXT tar to the hosting node from restoreEgress on a
	// credential signed by the SAME authority as the upload credentials,
	// with a Use the ingest refuses. backup.run refuses to start while a
	// restore holds a session, and a restore refuses while a run is in
	// flight: one party on the target at a time.
	restoreSessions := storage.NewRestoreSessions()
	restoreEgress := storage.NewRestoreEgress(backupAuthority, restoreSessions)
	appRestoreCfg := storage.RestoreAppConfig{
		NC:            busSrv.Conn(),
		SelfNodeID:    selfNodeID,
		Apps:          appsStore,
		Tiles:         catalogStore,
		Inventory:     invStore,
		Sessions:      restoreSessions,
		Egress:        restoreEgress,
		EgressBaseURL: publicBaseURL,
		Store:         backupStore,
	}
	runner.Register(storage.RestoreAppWorkflow(backupStore, appRestoreCfg))
	// storage.reconcile — #398: every five minutes, storage.inspect plus a
	// write probe on each claimed target, recorded on the row beside the
	// claim status, alerted on, and cited by backup.run's refusal. The gap
	// between weekly runs is where a target leaves the bus unnoticed.
	runner.Register(storage.TargetHealthWorkflow(backupStore, invStore))
	runner.Register(storage.RunWorkflow(backupStore, storage.RunConfig{
		Restores:  restoreSessions,
		ClusterID: strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
		// The operator's schedule — cadence and retention depth — read live
		// at the start of every run, the way the Due gate reads the cadence
		// on every tick; and the job ledger, read at pre-flight for the
		// manifests earlier runs kept, which is where every captured volume's
		// size on the target is recorded (storage/target_estimate.go).
		Settings: setupStore,
		Jobs:     jobStore,
		// The transport: the endpoint members land at, and the URL the
		// nodes are handed for it — the same public base the update
		// bundles are served from, so a node that can pull a bundle can
		// push a volume.
		Ingest:        backupIngest,
		IngestBaseURL: publicBaseURL,
		// Step 1 refuses a target on any other node: the archive is sealed here
		// and read by the agent beside it, and that is also what keeps the
		// staging root the api acts on coming from this host.
		SelfNodeID: selfNodeID,
		Sources: storage.IdentitySources{
			TrustDir:     trustDir,
			MeshStateDir: meshStateDir,
			BusDir:       filepath.Join(dataDir, "bus"),
		},
		// So a node whose agent does not answer a stage request is recorded
		// as offline, or as online with an agent that predates the verb —
		// whichever inventory says it is.
		Inventory: invStore,
		DB:        backupStore.DB(),
		DBPath:    dbPath,
		// §4.5's app-volume fan-out, and its only two inputs: what is installed
		// (and on which node) joined to the tile that classifies each of its
		// volumes. Both required — step 1 refuses a run that cannot enumerate
		// them rather than writing an archive that would silently contain no
		// app data.
		//
		// Tiles is the LIVE catalog — the same store /api/catalog serves from,
		// fetched bundle or floor — never catalog.MustLoad(). The embedded
		// tile set is a second copy of the catalog that predates the volume
		// classifications, and a fan-out reading it sees every app as
		// volume-less; see the catalogStore comment above.
		Apps:  appsStore,
		Tiles: catalogStore,
	}))
	runner.Register(bmc.PowerWorkflow(bmcSvc, invStore))
	// bmc.configure is registered after NewServer below — it needs the
	// server's SoL SessionManager to refuse swaps under a live console.

	// Abort any jobs left in-flight from a previous run before we expose
	// HTTP. v0 policy is honest-failure, not resume — see saga.go — EXCEPT a
	// control-plane self-update, which intentionally reboots the api mid-saga:
	// the decider defers it so ResumeSelfUpdates can finish it on the new slot.
	// Since #56 that applies to the parent system.update too, when self was
	// the last target of a fleet run — ResumeSystemUpdates finishes that one.
	runner.SetRecoverDecider(updater.SelfUpdateRecoverDecider(ctx, jobStore, selfNodeID))
	if err := runner.Recover(ctx); err != nil {
		log.Fatalf("rasputin-api: recover in-flight jobs: %v", err)
	}
	// Clear per-node update rows stranded in_progress by a job that already
	// reached a terminal state (#53). The OnTerminal hook closes this path
	// going forward; this one-shot sweep is what reaches back to rows stranded
	// before it existed, or by a process that died between failing the job and
	// firing the hook. Runs AFTER Recover so orphans it just failed are swept
	// in the same pass. Non-fatal: a stale history row is a display problem,
	// not a reason to refuse to start.
	if err := updater.ReconcileStrandedRows(ctx, updaterStore, jobStore); err != nil {
		log.Printf("rasputin-api: reconcile stranded node_updates: %v", err)
	}
	// Same sweep for backup-target claims: a row left `pending` by a process
	// that died mid-saga renders as a claim still running, forever.
	if err := storage.ReconcileStrandedRows(ctx, backupStore, jobStore); err != nil {
		log.Printf("rasputin-api: reconcile stranded backup_targets: %v", err)
	}
	// And for backup RUNS. A row left `running` by a process that died mid-saga
	// renders as a backup still in progress, forever — which is the one
	// appearance §4.4 says a failed backup must never be able to take.
	if err := storage.ReconcileStrandedRuns(ctx, backupStore, jobStore); err != nil {
		log.Printf("rasputin-api: reconcile stranded backup_runs: %v", err)
	}
	// Finish any self-update that rebooted us onto the new slot (no-op when
	// there isn't one). Non-blocking — reconciles in the background once the
	// co-located agent reconnects.
	updater.ResumeSelfUpdates(ctx, updaterStore, invStore, jobStore, runner, busSrv.Conn(), selfNodeID)
	// And the fleet run that self-update belonged to, if it was one (#56).
	// Ordered after ResumeSelfUpdates because it waits on the child that call
	// drives — starting it first would just poll for longer.
	updater.ResumeSystemUpdates(ctx, jobStore, runner, busSrv.Conn(), selfNodeID)

	invSvc := inventory.NewService(invStore, busSrv.Conn())
	// The bus TLS ladder and pin delivery. nil when the key did not load (see
	// above); every consumer treats nil as "bus TLS unavailable".
	var busTLSSvc *bustls.Service
	if busKey != nil {
		busTLSSvc = bustls.NewService(bustls.Config{
			Key:             busKey,
			Settings:        setupStore,
			StartMode:       busTLSMode,
			StartModePinned: busTLSModePinned,
			StartFault:      busTLSStart.Fault,
			Nodes: func(ctx context.Context) ([]*proto.Node, error) {
				nodes, err := invStore.List(ctx)
				if err == nil {
					invStore.Presence(ctx, nodes)
				}
				return nodes, err
			},
			Plaintext: busSrv.PlaintextClients,
			NC:        busSrv.Conn(),
			// offer → migrate waits for this: no self-update in flight, and
			// the controlplane's own agent reports its slot committed.
			Committed: func(ctx context.Context) (bool, string, error) {
				return updater.SelfBuildCommitted(ctx, jobStore, busSrv.Conn(), selfNodeID, 10*time.Second)
			},
			InFlight: func(ctx context.Context) ([]string, error) { return jobs.InFlight(ctx, jobStore) },
			// migrate → require closes job intake atomically with "nothing in
			// flight", so a job submitted while the bus server is replaced is
			// refused with a retryable error (503) rather than started on a
			// bus that is going away; intake reopens once the api's own
			// connection is back on the new server.
			Quiesce: runner.QuiesceIfIdle,
			Reopen:  runner.Reopen,
			// Replace the embedded server in this process with one that
			// refuses plaintext. The api process, its HTTP server and its bus
			// connection stay up; nodes rejoin over TLS on their own reconnect.
			RequireTLS: func(ctx context.Context) error { return busSrv.SetAllowNonTLS(ctx, false) },
			// Neither the new server nor one with the old options came up, or
			// the api's own connection could not rejoin: this api has no bus.
			// That is the state a bus that fails at boot is fatal in, and the
			// unit restarts the api the same way.
			NoBus: func(err error) {
				log.Fatalf("rasputin-api: bus: %v", err)
			},
		})
		busTLSForHold.Store(busTLSSvc)
		// A client connection closing can be the last plaintext one: re-decide
		// on the event, not on a clock.
		if err := busSrv.OnClientDisconnect(busTLSSvc.NoteDisconnect); err != nil {
			log.Printf("rasputin-api: bus TLS: %v — the switch to TLS-only waits for the next registration or job end instead", err)
		}
	}
	// On a firewall-role node's FIRST registration, seed the stock-equivalent
	// baseline firewall rules (Allow-DHCP-Renew / Allow-Ping / Allow-IGMP) as
	// real, visible, deletable intents. SeedBaselineRules is idempotent via a
	// persistent marker and never reseeds, so a baseline rule the operator
	// later deletes does not resurrect. Errors are logged and swallowed — a
	// seeding failure must never break node registration. Wired here (not in
	// the inventory package) to avoid an inventory→firewall import cycle,
	// mirroring auth.SetLoginHook → mesh.EnsureUser above.
	invSvc.SetOnNodeAdded(func(hookCtx context.Context, n *proto.Node) {
		// Firewall-only: seed the stock-equivalent baseline rules.
		if n.Role == proto.RoleFirewall {
			if _, err := firewall.SeedBaselineRules(hookCtx, fwStore, n.ID); err != nil {
				log.Printf("rasputin-api: seed baseline firewall rules for %s: %v", n.ID, err)
			}
		}
		// Auto-enroll every managed node — firewall INCLUDED — into the mesh so it
		// receives the mesh CA (needed to verify the control plane's TLS when
		// downloading update bundles) and a tailnet identity. The controlplane
		// self-enrolls during setup. Without this, a day-2 node added through the
		// wizard joins the bus but never the mesh, and its first update fails on the
		// bundle download with "certificate signed by unknown authority" (found on
		// bench-compute1 2026-06-22; and on the firewall 2026-07-02 once it became a
		// deployable A/B OTA target — the firewall was previously excluded here).
		// The DELETE /api/nodes cascade removes the headscale node + device.
		// This hook is best-effort fast-path only: the mesh.reconcile workflow's
		// converge_enrollment step retries any node this misses (e.g. one that
		// registered before Headscale finished bring-up), every reconcile tick.
		if slices.Contains(mesh.AutoEnrollRoles, n.Role) {
			spec, _ := json.Marshal(mesh.EnrollSpec{NodeID: n.ID})
			if _, err := runner.Submit(hookCtx, "mesh.enroll_node", spec, "auto-enroll"); err != nil {
				log.Printf("rasputin-api: auto mesh-enroll %s: %v", n.ID, err)
			} else {
				log.Printf("rasputin-api: auto-enrolling %s (%s) into the mesh", n.ID, n.Role)
			}
		}
	})
	// This node's own row takes its LAN address from lanWatch, not from the
	// co-located agent's default-route guess, and moves when the address does
	// (see SetSelfLANIP). The RASPUTIN_SELF_NODE_ID guard keeps a dev api, which
	// has no node of its own, from writing anything.
	if selfNodeID != "" {
		invSvc.SetSelfLANIP(selfNodeID, func() string { return ipString(lanWatch.PrimaryIP()) })
	}
	// The firewall agent registers on every bus (re)connect. A dns_forward that
	// moved while the firewall was away could not be applied then; this is the
	// fact that says it can be now (#431). The saga applies only a forward that
	// changed or never landed, so a routine reconnect costs one no-op job.
	// And the same fact hands the bus pin to a node that registered without
	// TLS while the ladder is at migrate (#448).
	onFirewallRegistration := dnsForwardOnFirewallRegistration(submitDNSForward)
	invSvc.SetOnRegistered(func(hookCtx context.Context, n *proto.Node) {
		onFirewallRegistration(hookCtx, n)
		if busTLSSvc != nil {
			busTLSSvc.OnRegistered(hookCtx, n)
		}
	})
	if err := invSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: inventory service: %v", err)
	}
	if busTLSSvc != nil {
		if err := busTLSSvc.Start(); err != nil {
			log.Printf("rasputin-api: bus TLS: %v", err)
		}
		defer busTLSSvc.Stop()
	}
	defer invSvc.Stop()
	if selfNodeID != "" {
		followLANPrimary(lanWatch, func(net.IP) {
			if err := invSvc.RefreshSelfLANIP(ctx); err != nil {
				log.Printf("rasputin-api: inventory: refresh this node's LAN IP: %v", err)
			}
		})
	}

	metricsSvc := metrics.NewService(metricsStore, busSrv.Conn())
	if err := metricsSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: metrics service: %v", err)
	}
	defer metricsSvc.Stop()

	// Authoritative DNS for the internal zone <cluster-id>.internal, plus the
	// <cluster>.local unicast name, both → the control plane's own LAN IP
	// (ADR-0004 §3/§8). Slice 1 serves CP-self answers only; node + app records
	// arrive with Slice 2. Binds each LAN address:53 by value — never 0.0.0.0 —
	// so systemd-resolved's 127.0.0.53 stub, which publishes the cluster's mDNS
	// .local (ADR-0003), is left untouched. A bind failure (no privilege on a
	// dev box) is logged and skipped, never fatal: a control plane that won't
	// start is worse than one without name resolution.
	//
	// The listeners follow lanWatch (#431): none while the node has no usable
	// LAN IPv4, started when one appears, rebound when the addresses on the
	// primary link change. It used to be one bind at start, on an address found
	// by a default-route lookup, so a control plane whose only address was the
	// no-DHCP fallback (no gateway, so no default route) never served DNS, and
	// one whose lease arrived or moved later kept its start-time bind.
	// nsResp is hoisted so the api server can hot-swap its AA-11 forwarding stub
	// after construction (below); nil when the nameserver is disabled/unstarted.
	var nsResp *nameserver.Responder
	if envOr("RASPUTIN_DNS", "on") != "off" {
		zone := "rasputin.internal"
		if id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")); id != "" {
			zone = id + ".internal"
		}
		// Project node + app A records live from inventory + apps, under the
		// **.lan subzone** (ADR-0004 §9): <hostname>.lan.<zone> → node LAN IP,
		// <app>.lan.<zone> → its target node's LAN IP. The bare base domain is the
		// tailnet name (MagicDNS / extra_records), so the CP nameserver serves LAN
		// IPs only under .lan and NXDOMAINs bare node/app names — a LAN-only client
		// can't route a tailnet IP anyway. Read on every query (store errors →
		// serve nothing that round, never crash).
		lanZone := "lan." + zone
		clusterSrc := nameserver.NewClusterSource(lanZone,
			func() []nameserver.NodeAddr {
				nodes, err := invStore.List(ctx)
				if err != nil {
					log.Printf("rasputin-api: nameserver node projection: %v", err)
					return nil
				}
				out := make([]nameserver.NodeAddr, 0, len(nodes))
				for _, n := range nodes {
					out = append(out, nameserver.NodeAddr{ID: n.ID, Hostname: n.Hostname, IP: net.ParseIP(n.LANIP)})
				}
				return out
			},
			func() []nameserver.AppRec {
				list, err := appsStore.List(ctx)
				if err != nil {
					log.Printf("rasputin-api: nameserver app projection: %v", err)
					return nil
				}
				out := make([]nameserver.AppRec, 0, len(list))
				for _, a := range list {
					out = append(out, nameserver.AppRec{Name: a.Name, TargetNode: a.TargetNode, ExposeLAN: a.ExposeLAN})
				}
				return out
			})
		nsResp = nameserver.NewResponder(zone,
			nameserver.NewSelfSource(zone, clusterHostname(), lanWatch.PrimaryIP),
			clusterSrc)
		nsListeners := nameserver.NewListeners(ctx, 53, nsResp)
		defer func() { _ = nsListeners.Close() }()
		followLANNameserver(lanWatch, nsListeners, zone)
	}

	// IDS alert subscriber — appends each firewall snort alert to a JSONL
	// file the obs Alloy tails (when EnableLoki + EnableIDSPipe are on).
	// Even with obs off, the file is still written so operators can
	// `tail -f` / `jq` it from disk. Path is under dataDir so it survives
	// the same way every other persistent state does.
	//
	// idsLogDir is passed to mustWireObs so the supervisor knows where to
	// mount the host dir into the Alloy container; same constant both
	// sides → no path-mismatch class of bug.
	idsLogDir := filepath.Join(dataDir, "obs", "ids-alerts")
	idsLogPath := filepath.Join(idsLogDir, "alerts.jsonl")
	idsWriter, err := ids.NewWriter(idsLogPath)
	if err != nil {
		log.Fatalf("rasputin-api: ids writer: %v", err)
	}
	defer func() { _ = idsWriter.Close() }()
	idsSvc := ids.NewService(idsWriter, busSrv.Conn())
	if err := idsSvc.Start(ctx); err != nil {
		log.Fatalf("rasputin-api: ids service: %v", err)
	}
	defer idsSvc.Stop()

	// Tier 2 observability — VictoriaMetrics sidecar + metrics fan-out.
	// Off by default so dev runs don't require Docker. The supervisor is
	// always constructed; the operator's stored obs.enabled setting decides
	// whether the stack actually runs, and Settings toggles it at runtime
	// through the obs.enable / obs.disable jobs below. RASPUTIN_OBS_ENABLED
	// only seeds that setting on a first boot.
	// See wiki design/control-plane/observability-stack.md §3.8.
	seedObsEnabled(ctx, setupStore)
	obsEnabled := func(ctx context.Context) (bool, error) {
		return setupStore.GetBool(ctx, setup.KeyObsEnabled, false)
	}
	obsSup, obsSink, obsStatus := mustWireObs(ctx, dataDir, selfNodeID, metricsSvc, idsLogDir, obsEnabled)
	defer func() {
		// Only tear down what we brought up. Stop shells out to `docker
		// compose stop`; on a never-started stack that's a pointless
		// subprocess, and on a host with no runtime it's a noisy one.
		if on, err := obsEnabled(context.Background()); err != nil || !on {
			return
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := obsSup.Stop(stopCtx); err != nil {
			log.Printf("rasputin-api: obs supervisor stop: %v", err)
		}
	}()
	// The operator-facing toggle. Registered here rather than with the other
	// workflows above because these close over the supervisor + sink that
	// mustWireObs just built. Runner.Register is mutex-guarded and workflows
	// resolve at Submit time, so late registration is safe.
	setObsEnabled := func(ctx context.Context, on bool) error {
		return setupStore.SetBool(ctx, setup.KeyObsEnabled, on)
	}
	setObsSink := func(on bool) {
		if on {
			metricsSvc.SetSink(obsSink)
			return
		}
		metricsSvc.SetSink(nil)
	}
	runner.Register(obs.EnableWorkflow(obsSup, setObsEnabled, setObsSink, func() bool {
		return dockerBinAvailable(obsDockerBin())
	}))
	runner.Register(obs.DisableWorkflow(obsSup, setObsEnabled, setObsSink))

	// Per-node observability collectors (Slice 1.2b, §3.10). Only in appliance
	// mode: the mTLS ingress the collectors write to is appliance-only
	// (obsIngestAddr), and dev has no compute/storage nodes. The reconcile
	// converges the fleet to the operator's obs opt-in — deploy collectors when
	// on, tear them down when off.
	var obsCollectorEntries []scheduler.Entry
	if obsIngestAddr != "" {
		ingressBaseURL, ingressServerName, err := obs.DeriveIngressEndpoint(publicBaseURL, obsIngestAddr)
		if err != nil {
			log.Fatalf("rasputin-api: obs collector ingress endpoint: %v", err)
		}
		// Mint (idempotently) each node's client-auth leaf under the mesh CA.
		// Renewal is the leaf sweep's job (collectorLeafSource), not this
		// function's: MintLeafToDisk returns the existing leaf until it enters
		// its renew window, and by then the sweep has already replaced it.
		mintCollectorLeaf := func(nodeID string) (certPEM, keyPEM, caPEM string, err error) {
			paths, err := mesh.MintLeafToDisk(meshCA,
				filepath.Join(dataDir, "tls", "collectors", nodeID),
				collectorLeafSpec(nodeID))
			if err != nil {
				return "", "", "", err
			}
			cert, err := os.ReadFile(paths.CertPath)
			if err != nil {
				return "", "", "", fmt.Errorf("read collector leaf cert: %w", err)
			}
			key, err := os.ReadFile(paths.KeyPath)
			if err != nil {
				return "", "", "", fmt.Errorf("read collector leaf key: %w", err)
			}
			return string(cert), string(key), string(meshCA.CertPEM), nil
		}
		runner.Register(obs.CollectorReconcileWorkflow(obs.CollectorReconcileDeps{
			Inv: invStore, Jobs: jobStore, Runner: runner, Enabled: obsEnabled,
		}))
		runner.Register(obs.CollectorDeployWorkflow(obs.CollectorDeployDeps{
			Inv: invStore, Mint: mintCollectorLeaf,
			IngressBaseURL: ingressBaseURL, ServerName: ingressServerName,
		}))
		runner.Register(obs.CollectorTeardownWorkflow())
		obsCollectorReconcileEvery := parseDurationOr(
			os.Getenv("RASPUTIN_OBS_COLLECTOR_RECONCILE_INTERVAL"), 5*time.Minute)
		obsCollectorEntries = append(obsCollectorEntries, scheduler.Entry{
			Kind: obs.CollectorReconcileKind, Interval: obsCollectorReconcileEvery,
			InitialDelay: 2 * time.Minute,
		})
		log.Printf("rasputin-api: obs collectors enabled — ingress %s (server_name %s)", ingressBaseURL, ingressServerName)
	}

	// Reconciliation tickers. One scheduler entry per drift-prone
	// subsystem; staggered so the bus doesn't stampede at startup. All
	// intervals are env-overridable (parsed by parseDurationOr below).
	// Defaults match the firewall + mesh §6 docs (5 min).
	fwReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_FW_RECONCILE_INTERVAL"), 5*time.Minute)
	appsReconcileEvery := parseDurationOr(os.Getenv("RASPUTIN_APPS_RECONCILE_INTERVAL"), 5*time.Minute)
	// meshReconcileEvery is parsed where the mesh service is built, above.
	// Mesh-CA leaves live a year and renew at <60d left (mesh.renewWindow); the
	// sweep re-checks that fact, so a daily tick is ample and cheap (it reads
	// each leaf's NotAfter and does nothing until one enters the window). The
	// old per-app name is still honoured for an operator who set it.
	leafSweepEvery := parseDurationOr(
		envOr("RASPUTIN_LEAF_SWEEP_INTERVAL", os.Getenv("RASPUTIN_APPS_LEAF_ROTATE_INTERVAL")),
		mesh.DefaultLeafSweepInterval)
	sched := scheduler.New(runner, append(append(reconcileEntries(fwReconcileEvery, appsReconcileEvery, meshReconcileEvery, leafSweepEvery), []scheduler.Entry{
		// storage.reconcile (#398): the claimed backup target's health, with
		// a write probe. Fires only while a target is claimed (Due).
		{
			Kind:         storage.TargetHealthJobKind,
			Interval:     parseDurationOr(os.Getenv("RASPUTIN_STORAGE_RECONCILE_INTERVAL"), proto.BackupTargetHealthInterval),
			InitialDelay: 2 * time.Minute,
			Due:          storage.TargetHealthDue(backupStore),
		},
		backupRunEntry(
			parseDurationOr(os.Getenv("RASPUTIN_BACKUP_CHECK_INTERVAL"), time.Hour),
			storage.DueFunc(backupStore, setupStore, true),
		),
	}...), obsCollectorEntries...))
	sched.Start(ctx)
	defer sched.Stop()
	// firewall.dns_forward runs the moment the primary LAN address changes, and
	// once at start for the address this boot came up on. Every control-plane
	// reboot without a DHCP reservation is such a change, and until the forward
	// follows, the firewall sends <cluster-id>.internal to an address this node
	// no longer holds.
	followLANPrimary(lanWatch, func(net.IP) { submitDNSForward("lan-address-change") })

	// This start applied an identity restore: once the mesh is up, kick a
	// reconcile so converge_trust re-delivers the restored mesh CA to every
	// node still trusting the one the restore replaced, and record on the
	// report what it found. See restore_trust.go.
	if restored && appliedRestore != nil {
		go kickTrustConvergenceAfterRestore(ctx, meshSvc, runner, jobStore, backupStore, appliedRestore.ID)
	}

	srv := apipkg.NewServer(jobStore, runner, invStore, invSvc, fwStore, appsStore, metricsStore, updaterStore, verifier, bundleDir, trustDir, meshSvc, bmcSvc, setupSvc, authSvc, obsStatus, busTokenStore, busSrv.Conn())
	// The SAME rotator closure the leaf-rotation workflow uses, so PATCH
	// /api/apps/{id} applies a LAN-exposure change (#197) to the proxy
	// immediately instead of leaving the .lan name resolving until the next
	// sweep. One rotator, two callers — a second one would differ in exactly
	// the case that matters, an offline node.
	srv.SetAppLeafRotator(rotateAppLeaf)
	// GET/PUT /api/bus/tls, and the live pin every Add-node seed carries.
	srv.SetBusTLS(busTLSSvc)
	srv.SetComposeStash(composeStash)
	// Node removal deletes the node's collector leaf from here — the same
	// directory mintCollectorLeaf writes under.
	srv.SetCollectorLeafDir(filepath.Join(dataDir, "tls", "collectors"))
	// The backup-target ledger, for GET/POST /api/backup/targets, and the
	// ingest endpoint the nodes upload sealed volumes to.
	srv.SetBackupStore(backupStore)
	srv.SetBackupIngest(backupIngest)
	// The app-volume restore surface (#291 phase 2): the listing and the
	// custody-checked submit, and the egress endpoint the nodes fetch from.
	srv.SetAppRestore(&appRestoreCfg, restoreEgress)
	// The first-run restore surface. A prepared restore asks the process to
	// exit: cancel the signal context so the ordinary shutdown runs, and mark
	// the exit non-zero so the unit restarts it onto the restored identity.
	srv.SetRestore(&storage.RestoreConfig{
		NC:         busSrv.Conn(),
		SelfNodeID: selfNodeID,
		DataDir:    dataDir,
		ClusterID:  strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
		Store:      backupStore,
	}, func() {
		log.Printf("rasputin-api: a restore is prepared; shutting down to restart onto the restored identity")
		requestRestoreExit()
		cancel()
	})

	// AA-11 DNS forwarding (ADR-0004 §10): reconcile the nameserver's off-zone
	// forwarding stub from the persisted setting, and hand the api the hook to
	// re-apply it when the operator toggles it. Blank upstream → inherit the CP's
	// DHCP resolver, falling back to a public resolver when that would loop
	// (detect-and-fall-back). Kept plain-typed so api needn't import nameserver.
	if nsResp != nil {
		applyDNS := func(ctx context.Context) (string, bool, error) {
			cfg, err := setupSvc.GetDNSForwarding(ctx)
			if err != nil {
				return "", false, err
			}
			if !cfg.Enabled {
				nsResp.SetForwarder(nil)
				return "", false, nil
			}
			up := nameserver.ResolveUpstream(cfg.Upstream, lanWatch.PrimaryIP(),
				nameserver.SystemUpstreams("/etc/resolv.conf", "/run/systemd/netif/leases"))
			nsResp.SetForwarder(nameserver.NewForwarder(nameserver.ForwarderConfig{
				Upstream: up.Addr,
				SelfIP:   lanWatch.PrimaryIP,
			}))
			return up.Addr, up.FellBack, nil
		}
		// Applied now, and again whenever the primary LAN address changes: the
		// inherited upstream skips our own address, and it comes from the DHCP
		// lease, so a lease arriving after start changes both inputs.
		followLANPrimary(lanWatch, func(net.IP) {
			if _, _, err := applyDNS(ctx); err != nil {
				log.Printf("rasputin-api: DNS forwarding apply: %v", err)
			}
		})
		srv.SetDNSForwardingApplier(applyDNS)
	}

	// Host LAN IP + MAC for the DNS-forwarding reservation guidance (AA-11) —
	// available whether or not the nameserver runs.
	srv.SetHostLANInfo(func() (string, string) {
		ip := lanWatch.PrimaryIP()
		if ip == nil {
			return "", ""
		}
		return ip.String(), hardwareAddrForIP(ip)
	})

	// bmc.configure: delivers the operator's Settings selection to the
	// host agent (bmc-settings.md §4); refuses while a console is open or
	// a bmc.power job is running. Registered here because it shares the
	// server's SoL SessionManager.
	runner.Register(bmc.ConfigureWorkflow(bmcSvc, invStore, setupStore, srv.BMCSessions(), func(ctx context.Context) (bool, error) {
		running, err := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusRunning})
		if err != nil {
			return false, err
		}
		for _, j := range running {
			if j.Kind == "bmc.power" {
				return true, nil
			}
		}
		return false, nil
	}))
	// Event-driven reconcile: re-push the selection when the host
	// re-registers stale (reflash / missed push). No ticker
	// (bmc-settings.md §4).
	stopBMCReconcile, err := bmc.StartReconcile(busSrv.Conn(), setupStore, func(ctx context.Context) (bool, error) {
		// Stand down while any bmc.configure job is queued or running —
		// mid-job the advertised and desired states legitimately differ.
		inflight, ferr := jobStore.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusQueued, jobs.StatusRunning})
		if ferr != nil {
			return false, ferr
		}
		for _, j := range inflight {
			if j.Kind == "bmc.configure" {
				return true, nil
			}
		}
		return false, nil
	}, func(ctx context.Context, kind string, spec json.RawMessage, createdBy string) error {
		_, serr := runner.Submit(ctx, kind, spec, createdBy)
		return serr
	})
	if err != nil {
		log.Fatalf("rasputin-api: bmc reconcile: %v", err)
	}
	defer stopBMCReconcile()

	// Event-driven status seed: when a host advertises bmc-targets,
	// sweep a read-only status query across them so every reachable
	// node has a power state before the first operator verb.
	stopBMCSeed, err := bmc.StartStatusSeed(busSrv.Conn(), bmcSvc)
	if err != nil {
		log.Fatalf("rasputin-api: bmc status seed: %v", err)
	}
	defer stopBMCSeed()

	// Web UI (Next.js static export). The OS image installs it at the
	// default path (see rasputin-os package/rasputin-api); dev boxes
	// usually don't have it, so the api quietly stays headless there and
	// `next dev` serves the UI on :3000 instead.
	uiDir := envOr("RASPUTIN_UI_DIR", "/usr/share/rasputin/ui")
	if _, err := os.Stat(filepath.Join(uiDir, "index.html")); err == nil {
		srv.SetUIDir(uiDir)
		log.Printf("rasputin-api: serving web UI from %s", uiDir)
	} else {
		log.Printf("rasputin-api: no web UI at %s (%v); serving API only", uiDir, err)
	}

	// Real alerting (Slice 1.5): open the persisted alerts store and
	// wire a Service that merges aggregator + persisted views. Always
	// on — the store is shared with the rest of the api's SQLite and
	// is cheap when no rules are firing. The rule sync below and the
	// /ws/alerts push are no-ops until vmalert (in the obs compose
	// stack) reports an alert.
	alertsStore, err := alerts.OpenStore(ctx, dbPath)
	if err != nil {
		log.Fatalf("rasputin-api: alerts store: %v", err)
	}
	defer alertsStore.Close()
	alertsSvc := alerts.New(invStore, jobStore, appsStore, setupSvc, alertsStore, busSrv.Conn(), busAuthEnforce)
	// Bus TLS posture: a pinned mode below require, or a bus key that did not
	// load, is a standing warning like bus-auth-off.
	if busTLSSvc != nil {
		alertsSvc.SetBusTLSAlert(busTLSSvc.Alert)
	} else {
		alertsSvc.SetBusTLSAlert(bustls.UnavailableAlert)
	}
	// A join token holds one live session: when two presenters take it from
	// each other, the token is in use from more than one place and the
	// operator has to see it (#500). Nothing is reported while no token has
	// been taken over.
	alertsSvc.SetBusSessionAlerts(busTokenStore.SessionAlerts)
	// Per-app backup state (design/storage.md §4.4, #298): one derivation over
	// the backup ledger, the fan-out records in the job ledger, the installed
	// apps joined to the LIVE catalog, and the schedule — read by the /api/apps
	// rows (the OVERDUE tile) and by the alerts aggregator (the alert), so the
	// two surfaces cannot disagree. `true` is the schedule's default-on, the
	// same value the scheduler's gate is given.
	backupStates := storage.NewBackupStates(backupStore, jobStore, appsStore, catalogStore, setupStore, true)
	srv.SetBackupStates(backupStates)
	alertsSvc.SetBackupStates(backupStates)
	// Backup-target health (#398): one crit alert per claimed target the
	// five-minute poll found missing, unmounted, unwritable or unreachable.
	alertsSvc.SetBackupTargets(backupStore)
	// OFF BUS vs OFFLINE (#401): the same join /api/nodes reads.
	alertsSvc.SetMeshMembership(meshSvc.Membership)
	srv.SetAlertsService(alertsSvc)
	// Rule alerts: vmalert evaluates the rules on its own schedule and
	// writes its verdicts to VictoriaMetrics as ALERTS series; nothing calls
	// the api. This loop reads them back and mirrors them into the alerts
	// store (fire, resolve). See alerts.RunRuleSync for why it is a periodic
	// re-read and obs.RuleAlertFreshness for the staleness bound.
	ruleAlerts, err := obs.NewRuleAlertsClient(obs.RuleAlertsClientConfig{Supervisor: obsSup})
	if err != nil {
		log.Fatalf("rasputin-api: rule alerts client: %v", err)
	}
	go alertsSvc.RunRuleSync(ctx, func(ctx context.Context) ([]alerts.FiringRule, error) {
		on, err := obsEnabled(ctx)
		if err != nil {
			return nil, err
		}
		if !on {
			// Observability is off, so vmalert is not running and nothing
			// it last reported is current: nothing is firing.
			return nil, nil
		}
		firing, err := ruleAlerts.Firing(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]alerts.FiringRule, 0, len(firing))
		for _, a := range firing {
			out = append(out, alerts.FiringRule{
				Labels:   a.Labels,
				ActiveAt: a.ActiveAt,
				Summary:  obs.RuleAlertSummary(a.Labels),
			})
		}
		return out, nil
	}, obs.VMAlertEvaluationInterval)
	// Update discovery: the control plane reads signed releases directly from
	// each component's PUBLIC source repo over anonymous HTTPS — no token on the
	// appliance (ADR-0002; the rasputin-releases mirror is retired). Authenticity
	// is gated by the bundle signature, not repo privacy. RASPUTIN_RELEASE_API_BASE
	// is overridable for a proxy/CDN or tests.
	releaseChannel := envOr("RASPUTIN_RELEASE_CHANNEL", "stable")
	releaseAPIBase := envOr("RASPUTIN_RELEASE_API_BASE", "https://api.github.com")
	// The SAME verifier that gates an OTA install also gates the release
	// manifest the update decision is made from (geekdojo/geekdojo-brain#527) —
	// one verifier, bound to the release purpose, not a second one for
	// metadata. A control plane with no trust root passes a verifier that
	// refuses everything, so components at or above their signing floor fail to
	// resolve instead of resolving unverified.
	srv.SetReleaseSource(releases.NewGithubPublicSource(releaseAPIBase, verifier), releaseChannel)
	srv.SetReleaseDownloadBase(envOr("RASPUTIN_RELEASE_DOWNLOAD_BASE", "https://github.com"))
	log.Printf("rasputin-api: update channel = %s (direct from source repos)", releaseChannel)

	// App catalog polling (ADR-0006). catalogStore itself is built above,
	// before the backup workflow registers, because the fan-out reads it; the
	// poller replaces its floor with the newest signed catalog it can verify.
	catalogPoller := catalogsync.NewPoller(
		catalogsync.NewFetcher(
			envOr("RASPUTIN_CATALOG_REPO", ""),
			envOr("RASPUTIN_CATALOG_API_BASE", releaseAPIBase),
			releaseChannel,
		),
		catalogStore,
	)
	srv.SetCatalogSync(catalogStore, catalogPoller)
	go catalogPoller.Run(ctx)
	{
		v, fetched, note := catalogStore.State()
		src := "embedded floor"
		if fetched {
			src = "verified fetch"
		}
		log.Printf("rasputin-api: app catalog v%d (%s), polling %s every %s%s",
			v, src, releaseChannel, catalogsync.DefaultInterval,
			map[bool]string{true: " — " + note, false: ""}[note != ""])
	}

	handler := srv.Handler()

	// With HTTPS on, the plain-HTTP listener demotes to the bootstrap
	// surface (trust page + CA download + healthz; everything else 302s to
	// https). With HTTPS off — every dev run — it serves the full handler
	// exactly as before.
	httpHandler := handler
	var httpsSrv, obsIngestSrv *http.Server
	if httpsAddr != "" {
		// Served from memory through GetCertificate rather than from files at
		// ListenAndServeTLS, so a LAN address change re-mints the leaf's IP SAN
		// without a restart (#431).
		leaf := &apiLeaf{mint: func(lanIP net.IP) (mesh.LeafPaths, error) {
			return ensureAPILeaf(meshCA, dataDir, lanIP)
		}}
		// The api's own HTTPS leaf joins the sweep. Until now nothing renewed
		// it: it was minted at start and re-minted only when the primary LAN
		// address changed, so a controlplane that neither restarted nor moved
		// would have served it past its NotAfter. The reload hook swaps the
		// fresh bytes into the in-memory certificate both TLS listeners read
		// per handshake, so the HTTPS surface and the mTLS ingress pick it up
		// together and neither needs a restart.
		if err := leafSweeper.Register(mesh.LeafConsumer{
			Name: "api-https",
			Dir:  filepath.Join(dataDir, "tls", "api"),
			Spec: func() (mesh.LeafSpec, error) {
				hostname, _ := os.Hostname()
				return apiLeafSpec(hostname, lanWatch.PrimaryIP()), nil
			},
			Reload: func(context.Context, mesh.LeafPaths) error {
				return leaf.refresh(lanWatch.PrimaryIP())
			},
		}); err != nil {
			log.Fatalf("rasputin-api: leaf sweep: %v", err)
		}
		httpsSrv = &http.Server{
			Addr:              httpsAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			// http/1.1 only: with h2 offered, Chrome rides WebSockets on an
			// RFC 8441 extended-CONNECT h2 stream (Go ≥1.25 advertises it),
			// and the SoL console's browser→api leg silently stalled on the
			// bench (2026-07-26) — frames sent, never delivered to the
			// handler. Pin ALPN to the classic Upgrade path until WS-over-h2
			// is deliberately validated; the dashboard loses nothing.
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			},
		}
		httpsSrv.TLSConfig.GetCertificate = leaf.getCertificate
		// The obs mTLS ingress shares the api's own server leaf for its
		// identity (started with the same cert/key below, once minted) but
		// adds RequireAndVerifyClientCert against the mesh CA — a per-node
		// collector authenticates purely by presenting a mesh-CA-signed client
		// leaf, whose node_id is the cert CN (see obs_ingest.go). Constructed
		// synchronously here (like httpsSrv) so shutdown can reach it; it only
		// starts serving inside the clock-gated goroutine, after the leaf exists.
		if obsIngestAddr != "" {
			clientCAs := x509.NewCertPool()
			clientCAs.AddCert(meshCA.Cert)
			obsIngestSrv = &http.Server{
				Addr:              obsIngestAddr,
				Handler:           srv.ObsIngestHandler(),
				ReadHeaderTimeout: 10 * time.Second,
				TLSConfig: &tls.Config{
					MinVersion:     tls.VersionTLS12,
					ClientAuth:     tls.RequireAndVerifyClientCert,
					ClientCAs:      clientCAs,
					GetCertificate: leaf.getCertificate,
				},
			}
			// A collector is admitted only while its node is a current member
			// holding a live join token: checked once per connection in the
			// handshake, from the in-memory node registry, and a removal or
			// revoke closes the node's open connections (obs_ingest_conns.go).
			if err := srv.WireObsIngest(obsIngestSrv, invStore.Registry()); err != nil {
				log.Fatalf("rasputin-api: obs ingress: %v", err)
			}
		}
		// HTTP demotes to the bootstrap surface right away so the node is
		// reachable immediately; HTTPS comes up asynchronously once the clock
		// is trustworthy (below). Minting the leaf must NOT block main() —
		// this unit is Type=notify with the default ~90s start timeout, and a
		// no-RTC node may wait tens of seconds for NTP.
		httpHandler = srv.BootstrapHandler()
		go func() {
			// Don't mint the API leaf against an untrusted clock. A no-RTC node
			// (e.g. Pi 5) boots to a bogus pre-NTP time; minting then anchors
			// the cert's validity window in the past, so the browser reports an
			// "expired" (or "not yet valid") certificate even though the image
			// is fine. The gate waits — bounded — for systemd-timesyncd to
			// synchronize first, and says so if it gives up, so a genuinely
			// offline node still eventually serves HTTPS, degraded and logged
			// loudly. See provisioning.md "Time sync".
			//
			// It is the SAME gate the Mesh CA hands to every other leaf mint,
			// so this wait is the one the whole process spends, and it happens
			// here — off the startup path, where a wait is affordable — rather
			// than inside whichever mint happens to be first.
			clockGate.ok()
			if ctx.Err() != nil {
				return // shutting down before the clock settled
			}
			if err := leaf.load(lanWatch.PrimaryIP()); err != nil {
				log.Fatalf("rasputin-api: https leaf: %v", err)
			}
			// Re-mint when the primary LAN address changes. A failure keeps the
			// previous leaf in service and is not retried on a timer; the next
			// address change, or a restart, tries again.
			followLANPrimary(lanWatch, func(ip net.IP) {
				if err := leaf.load(ip); err != nil {
					log.Printf("rasputin-api: https leaf re-mint for LAN address %q: %v (previous leaf still served)", ipString(ip), err)
				}
			})
			log.Printf("rasputin-api: https listening on %s (leaf %s)", httpsAddr, filepath.Join(dataDir, "tls", "api", "leaf.pem"))
			// Bring up the obs mTLS ingress on the same leaf, in its own
			// goroutine so it serves alongside (not after) HTTPS. Both listeners
			// read the leaf per handshake through leaf.getCertificate, so a
			// re-mint reaches them together.
			if obsIngestSrv != nil {
				go func() {
					log.Printf("rasputin-api: obs mTLS ingress listening on %s", obsIngestAddr)
					if err := obsIngestSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Fatalf("rasputin-api: obs ingress: %v", err)
					}
				}()
			}
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("rasputin-api: https: %v", err)
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind before saying so, and before telling systemd the api is ready: the
	// "listening" line and READY=1 are then facts a client can act on, not a
	// race with the bind.
	httpLn, err := net.Listen("tcp", httpAddr)
	if err != nil {
		log.Fatalf("rasputin-api: http: %v", err)
	}
	log.Printf("rasputin-api: http listening on %s", httpAddr)
	go func() {
		if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("rasputin-api: http: %v", err)
		}
	}()

	// systemd integration: declare startup complete, then keep the
	// watchdog fed for as long as the liveness probe (a trivial SQLite
	// query) keeps passing. See internal/sdnotify for the war story.
	sdnotify.Ready()
	sdnotify.StartWatchdog(ctx, func(pctx context.Context) error {
		_, err := authStore.CountUsers(pctx)
		return err
	})

	<-ctx.Done()
	log.Println("rasputin-api: shutting down")

	// Hard cap: exit within 20s no matter which teardown step wedges, so we never
	// sit at systemd's 90s SIGKILL default (the stop job seen on the n100 console).
	// runner.Wait() below was UNBOUNDED and could block shutdown indefinitely; the
	// deferred subsystem stops (obs/sched/ids/alerts/bus) are best-effort within
	// this window. See #8.
	go func() {
		time.Sleep(20 * time.Second)
		log.Println("rasputin-api: shutdown deadline (20s) exceeded; forcing exit")
		os.Exit(0)
	}()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	if httpsSrv != nil {
		_ = httpsSrv.Shutdown(shutCtx)
	}
	if obsIngestSrv != nil {
		_ = obsIngestSrv.Shutdown(shutCtx)
	}
	// Bound the job-runner drain — a stuck worker must not wedge shutdown (#8).
	runnerDone := make(chan struct{})
	go func() { runner.Wait(); close(runnerDone) }()
	select {
	case <-runnerDone:
	case <-time.After(5 * time.Second):
		log.Println("rasputin-api: job runner did not drain in 5s; proceeding to exit")
	}
}

// clockGateTimeout bounds how long ensureAPILeaf waits for the wall clock to
// NTP-synchronize before minting the HTTPS leaf. Kept under the api unit's
// ~90s Type=notify start timeout headroom — but it runs in the HTTPS
// goroutine, off the readiness path, so it never trips that timeout anyway.
const clockGateTimeout = 90 * time.Second

// clockSyncDir / clockSyncMarker locate systemd-timesyncd's synchronization
// signal. timesyncd touches the marker on its first successful sync; this is
// the same file time-sync.target / systemd-time-wait-sync key on. Package vars
// (not consts) so tests can point them at a temp dir.
var (
	clockSyncDir    = "/run/systemd/timesync"
	clockSyncMarker = "/run/systemd/timesync/synchronized"
)

// waitForTrustworthyClock blocks until systemd-timesyncd reports the wall clock
// has synchronized (via NTP), ctx is cancelled, or timeout elapses. It returns
// true only when synchronization was observed. On a host without
// systemd-timesyncd (every dev run / CI — no /run/systemd/timesync) it returns
// true immediately: the gate exists solely to stop a no-RTC appliance from
// minting its TLS leaf against a bogus pre-NTP clock (the "expired cert"
// failure). The deadline uses the monotonic clock, so an NTP step mid-wait
// does not distort it.
func waitForTrustworthyClock(ctx context.Context, timeout time.Duration) bool {
	if _, err := os.Stat(clockSyncDir); err != nil {
		return true // not a systemd-timesyncd system; nothing to wait for
	}
	if _, err := os.Stat(clockSyncMarker); err == nil {
		return true // already synchronized
	}
	log.Printf("rasputin-api: waiting up to %s for the system clock to NTP-synchronize before minting the HTTPS leaf…", timeout)
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
			if _, err := os.Stat(clockSyncMarker); err == nil {
				return true
			}
			if !time.Now().Before(deadline) {
				return false
			}
		}
	}
}

// ensureAPILeaf mints (or reuses — MintLeafToDisk is idempotent with
// SAN-drift and <60d re-mint logic) the api's own HTTPS server leaf under
// the Mesh CA. Lives at <dataDir>/tls/api/leaf.{pem,key}, parallel to the
// Headscale leaf at <dataDir>/mesh/headscale/certs/.
func ensureAPILeaf(meshCA *mesh.MeshCA, dataDir string, lanIP net.IP) (mesh.LeafPaths, error) {
	hostname, _ := os.Hostname()
	spec := apiLeafSpec(hostname, lanIP)
	return mesh.MintLeafToDisk(meshCA, filepath.Join(dataDir, "tls", "api"), spec)
}

// apiLeafSpec builds the SAN set for the api's HTTPS leaf:
//
//	DNS: rasputin.local (the mDNS name the OS image advertises via
//	     systemd-resolved), localhost (same-host curl/debug, and
//	     symmetric with the Headscale leaf), the machine hostname, and
//	     <hostname>.local when the hostname is a bare label.
//	IP:  127.0.0.1 plus the discovered primary LAN IP, so operators who
//	     browse by address before mDNS resolves still get a clean lock.
//
// MintLeafToDisk's SAN-drift check re-mints automatically when any of
// these change (new hostname, node moved subnets).
func apiLeafSpec(hostname string, lanIP net.IP) mesh.LeafSpec {
	dns := []string{"rasputin.local", "localhost"}
	seen := map[string]bool{"rasputin.local": true, "localhost": true}
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && !seen[name] {
			seen[name] = true
			dns = append(dns, name)
		}
	}
	host := strings.ToLower(strings.TrimSpace(hostname))
	add(host)
	if host != "" && !strings.Contains(host, ".") {
		add(host + ".local")
	}
	ips := []net.IP{net.IPv4(127, 0, 0, 1)}
	if lanIP != nil {
		ips = append(ips, lanIP)
	}
	return mesh.LeafSpec{
		CommonName:  "rasputin.local",
		DNSNames:    dns,
		IPAddresses: ips,
	}
}

// reconcileEntries is the fixed part of the api's schedule: the drift
// reconciles, whose job is to notice divergence nobody announced, and the
// leaf-rotation sweep.
//
// firewall.dns_forward is deliberately absent. It used to tick here every
// fwReconcileEvery, re-deriving the forward from the address on a timer. It is
// now submitted on the facts that change its inputs — the LAN address, the
// firewall agent registering, the mode, an edit to the forward — so a tick would
// only re-check what those already cover (#431). firewall.reconcile keeps its
// own entry and cadence; it compares observed state and never rewrites the
// forward.
func reconcileEntries(fwReconcileEvery, appsReconcileEvery, meshReconcileEvery, leafSweepEvery time.Duration) []scheduler.Entry {
	return []scheduler.Entry{
		{Kind: "firewall.reconcile", Interval: fwReconcileEvery, InitialDelay: 30 * time.Second},
		{Kind: "apps.reconcile", Interval: appsReconcileEvery, InitialDelay: 60 * time.Second},
		{Kind: "mesh.reconcile", Interval: meshReconcileEvery, InitialDelay: 90 * time.Second},
		// ONE entry for leaf renewal, whatever holds the leaf. apps.leaf_rotate
		// is still a workflow — the sweep submits it, and the PATCH handler
		// still drives one app's leaf directly — but it no longer has a tick of
		// its own, because two ticks renewing certificates is two places to
		// look when one lapses.
		{Kind: mesh.LeafSweepKind, Interval: leafSweepEvery, InitialDelay: 2 * time.Minute},
	}
}

// backupRunEntry is the scheduler entry for backup.run (§4.1): weekly by
// default, overridable per installation.
//
// The Interval here is a CHECK interval, not the cadence — the cadence lives in
// the settings table and the Due gate reads it on every tick, so an operator
// changing it does not have to restart the api. Hourly is well below the
// one-hour floor an override may set (storage.MinBackupCadence), so no cadence
// can outrun the check.
//
// The spec names its reason explicitly. The scheduler substitutes {} for an
// empty spec, and storage.ParseRunSpec reads anything that is not "scheduled"
// as manual — so an entry without one recorded every scheduled run as a press
// of Back up now, and the run list could not tell the two apart.
func backupRunEntry(checkEvery time.Duration, due func(context.Context) (bool, string)) scheduler.Entry {
	return scheduler.Entry{
		Kind:         storage.RunJobKind,
		Spec:         json.RawMessage(`{"reason":"` + storage.ReasonScheduled + `"}`),
		Interval:     checkEvery,
		InitialDelay: 3 * time.Minute,
		Due:          due,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// hardwareAddrForIP returns the MAC of the interface holding ip, best-effort
// ("" if not found). Used to recommend a DHCP reservation for the control plane
// (AA-11) so its address survives reboots.
func hardwareAddrForIP(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var aip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				aip = v.IP
			case *net.IPAddr:
				aip = v.IP
			}
			if aip != nil && aip.Equal(ip) {
				return iface.HardwareAddr.String()
			}
		}
	}
	return ""
}

// clusterHostname returns the cluster's mDNS name — "<cluster-id>.local" — or
// "" when this process is not running on a provisioned node.
//
// RASPUTIN_CLUSTER_ID is written into node.env by firstboot and by nothing
// else, so its PRESENCE is the signal "I am a provisioned appliance". That is
// what lets the appliance defaults below derive a name while dev keeps its
// localhost defaults untouched — the alternative, deriving unconditionally,
// would rename every developer's origin and break the local passkey flow.
//
// Per ADR-0003 the id defaults to "rasputin", so a node that predates
// per-cluster naming — or any node whose operator never chose a name —
// derives exactly the values the OS image used to hardcode. That is the
// mechanism by which per-cluster naming ships with no migration.
func clusterHostname() string {
	id := strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID"))
	if id == "" {
		return ""
	}
	return id + ".local"
}

// applianceOr returns the appliance value derived from the cluster name, or
// devDefault when there is no cluster id (i.e. a dev box). Callers still let an
// explicit env var win — this only supplies the default.
func applianceOr(appliance func(host string) string, devDefault string) string {
	if h := clusterHostname(); h != "" {
		return appliance(h)
	}
	return devDefault
}

// busPreseedPath is where the controlplane reads its provisioning matched-set
// token preseed (hashes + node bindings). firstboot copies it here from the
// seed FAT. Overridable for tests / non-default layouts.
func busPreseedPath(dataDir string) string {
	return envOr("RASPUTIN_BUS_PRESEED", filepath.Join(dataDir, "bus", "preseed.json"))
}

// loadBusTokenState takes the revocation tombstone file into use (busauth
// tombstones.go), then preloads the matched-set preseed. Tombstones come first:
// they re-apply every revocation this controlplane has made to a database that
// lost or never saw it (a lost database, a restore), and the preload skips
// tombstoned hashes. If the tombstone file cannot be read, the preseed is NOT
// loaded: it may re-admit a token the unreadable file revoked. Nodes it would
// have loaded stay refused until the file is fixed — fail closed. It returns
// how many preseed tokens it loaded.
func loadBusTokenState(ctx context.Context, store *busauth.Store, dataDir string) int {
	added, reapplied, err := store.UseTombstoneFile(ctx, busTombstonePath(dataDir))
	if err != nil {
		log.Printf("rasputin-api: ⚠️  bus token tombstones: %v — NOT loading the preseed this start, and revocations this run are recorded in the database only; fix or move the file aside (after checking it) and restart", err)
		return 0
	}
	if added > 0 || reapplied > 0 {
		log.Printf("rasputin-api: bus token tombstones: %d added to the file from the database, %d revocation(s) re-applied to the database", added, reapplied)
	}
	n, err := loadBusPreseed(ctx, store, busPreseedPath(dataDir))
	if err != nil {
		log.Printf("rasputin-api: bus token preseed: %v (continuing)", err)
		return 0
	}
	if n > 0 {
		log.Printf("rasputin-api: preloaded %d bus token(s) from provisioning seed", n)
	}
	return n
}

// busTombstonePath is the revocation tombstone file: in the bus directory,
// beside the default preseed.json and bus.key, which is the directory the
// identity archive takes it from (storage.IdentitySources.BusDir) and a
// restore merges it back into.
func busTombstonePath(dataDir string) string {
	return filepath.Join(dataDir, "bus", busauth.TombstoneFileName)
}

// loadBusPreseed reads a JSON array of {hash,nodeId,label} and preloads it into
// the token store. A missing file is normal (not every install is a pre-paired
// matched set) and returns (0, nil). Idempotent via Store.PreloadHashes.
func loadBusPreseed(ctx context.Context, store *busauth.Store, path string) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	toks, err := busauth.ParsePreseed(data)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return store.PreloadHashes(ctx, toks)
}

// logUnboundBusTokens reports live legacy unbound join tokens at startup. Every
// token is bound to one node (geekdojo-brain#423) and the store refuses an
// unbound one at the bus, so a node still seeded with one cannot join; this
// line is how that node is diagnosed. Such a token appears in GET
// /api/bus/tokens with no nodeId and is revoked with DELETE
// /api/bus/tokens/{id}; the node is re-provisioned with a bound token.
func logUnboundBusTokens(ctx context.Context, store *busauth.Store) {
	n, err := store.CountActiveUnbound(ctx)
	if err != nil {
		log.Printf("rasputin-api: counting unbound bus tokens: %v", err)
		return
	}
	if n > 0 {
		log.Printf("rasputin-api: WARNING %d live UNBOUND bus join token(s) — the bus refuses them, so a node seeded with one cannot join; list them with GET /api/bus/tokens (no nodeId), revoke them, and re-provision those nodes with a token bound to their node id", n)
	}
}

// logRolelessBusTokens reports live bound join tokens whose row names no node
// role at startup. Every token is bound to a role (busauth role.go); the store
// fills the role wherever the row says what it is, and refuses the rest at the
// bus, so a node still seeded with one cannot join. Such a token appears in GET
// /api/bus/tokens with no role; the operator revokes it and mints a
// replacement with the node's role.
func logRolelessBusTokens(ctx context.Context, store *busauth.Store) {
	n, err := store.CountActiveRoleless(ctx)
	if err != nil {
		log.Printf("rasputin-api: counting role-less bus tokens: %v", err)
		return
	}
	if n > 0 {
		log.Printf("rasputin-api: WARNING %d live bus join token(s) name no node role — the bus refuses them, so a node seeded with one cannot join; list them with GET /api/bus/tokens (no role), revoke them, and mint replacements with the node's role", n)
	}
}

// ensureSelfAgentToken makes sure the controlplane's own agent has a live join
// token bound to selfNodeID at path (busauth.Store.EnsureAgentToken), and says
// what it did. A dev api with no self node id has no co-located agent to mint
// for and skips it.
//
// A failure is logged, not fatal: a controlplane that will not start cannot be
// used to fix anything (#89). Its own agent then stays off the bus — refused
// for want of a token, and reported offline in the UI — until a restart
// succeeds; every other node is unaffected.
func ensureSelfAgentToken(ctx context.Context, store *busauth.Store, path, selfNodeID string) {
	if selfNodeID == "" {
		log.Printf("rasputin-api: no RASPUTIN_SELF_NODE_ID — not minting a bus token for a co-located agent (dev); a local agent needs RASPUTIN_CP_JOIN_TOKEN, or RASPUTIN_BUS_AUTH=off on this api")
		return
	}
	reason, err := store.EnsureAgentToken(ctx, path, selfNodeID)
	// Every value is %q-formatted: the node id and path come from this
	// process's own environment, and reason and err are built from them.
	switch {
	case err != nil && reason != "":
		log.Printf("rasputin-api: minted a bus token for this controlplane's agent %q at %q (%q), but: %q", selfNodeID, path, reason, err.Error())
	case err != nil:
		log.Printf("rasputin-api: ⚠️  bus token for this controlplane's agent %q at %q: %q — its agent cannot join the bus until the api starts successfully", selfNodeID, path, err.Error())
	case reason != "":
		log.Printf("rasputin-api: minted a bus token for this controlplane's agent %q at %q: %q", selfNodeID, path, reason)
	default:
		log.Printf("rasputin-api: bus token for this controlplane's agent %q at %q is live", selfNodeID, path)
	}
}

// randomSecret returns a 32-byte hex secret for the bus AuthUser. Generated
// per boot; only ever used by the api's own in-process connection, so it never
// needs to persist.
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// secureCookies decides whether the session and pending-auth cookies carry
// the Secure attribute.
//
// It is DERIVED from whether this process terminates TLS, rather than read
// from a standalone env var, because `httpsAddr != ""` is the exact condition
// under which the cookie actually travels over TLS: it is the same value that
// starts the HTTPS listener AND demotes the plain-HTTP listener to the
// bootstrap surface, where everything but the trust page and healthz 302s to
// https. So whenever this returns true, an authenticated request cannot be
// served over plaintext, and whenever it returns false there is no https
// listener for a Secure cookie to be sent to.
//
// It previously read `os.Getenv("RASPUTIN_SECURE_COOKIES") == "1"` — opt-in,
// defaulting to OFF. That variable was set nowhere in rasputin-control-plane,
// rasputin-os or rasputin-openwrt-firewall, so the 7-day passkey session
// cookie shipped without Secure on every appliance, even though the appliance
// serves https (the OS image's unit sets RASPUTIN_HTTPS_ADDR=:443). The
// default was the bench value and production had to remember to opt in; a
// derived value cannot be forgotten the way an env var can.
//
// The override remains for deployments this process cannot observe — TLS
// terminated by a reverse proxy in front of a plain-HTTP api (force true), or
// an https listener reached over a path where Secure would strand the session
// (force false). Unset means derived, which is what every current deployment
// wants.
func secureCookies(httpsAddr string, override *bool) bool {
	if override != nil {
		return *override
	}
	return httpsAddr != ""
}

// envBoolPtr returns nil when the env var is unset (so the config's own
// default applies) and a non-nil bool when explicitly set. "1"/"true"/"yes"
// → true; anything else → false. The pointer return shape is what the obs
// config uses for tri-state ("not set" vs "explicitly false" vs "true").
func envBoolPtr(key string) *bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		t := true
		return &t
	default:
		f := false
		return &f
	}
}

// updateTrustEnv named the OS-update verifier's mode. The only mode left is
// the required one, so the variable no longer selects anything — it is read
// solely to tell an operator whose start-up scripts still set it that it has
// stopped doing what it used to.
const updateTrustEnv = "RASPUTIN_UPDATE_TRUST"

// wireBundleVerifier builds the OS-update signature verifier.
//
// There is exactly one posture now: <trustDir>/root-ca.pem must load, and if
// it does not the verifier is UNAVAILABLE and every artifact is refused.
//
// ⚠️ THERE USED TO BE A SECOND, and before that the missing file selected it by
// itself — the same class of bug as the 2026-09-01 storage incident and the
// mock-mesh fallback #220 removed: an absent prerequisite silently became a
// confident answer. Here the answer was "this OS update bundle is fine to
// install", produced without checking a single signature, on the artifact that
// decides what code a node boots. Making it opt-in by name kept the answer
// available to anyone who typed the name. It is now unreachable: the verifier
// delegates to artifactsig, which has no permissive mode to select. A dev box
// gets a real PKI from scripts/pki-init.sh, whose release leaf carries the
// same purpose OID the release pipeline's does.
//
// NOT log.Fatalf, for the reason #89 settled: an appliance that will not start
// is unreachable and unfixable. The api boots, /healthz answers, every other
// page works; only bundle upload and staging refuse, naming the missing file.
func wireBundleVerifier(trustDir string) *updater.Verifier {
	if mode := strings.ToLower(strings.TrimSpace(os.Getenv(updateTrustEnv))); mode != "" && mode != "require" {
		log.Printf("rasputin-api: ⚠️  %s=%q is ignored — OS update artifacts are verified against "+
			"%s/root-ca.pem and there is no longer any mode that skips the check. Run scripts/pki-init.sh "+
			"on a dev box with no PKI, and drop the variable.", updateTrustEnv, mode, trustDir)
	}
	v := updater.NewVerifier(trustDir)
	if !v.Available() {
		log.Printf("rasputin-api: ⚠️  OS UPDATE VERIFICATION UNAVAILABLE: %s. No unverified mode was "+
			"substituted — an update artifact nobody checked is the one thing that decides what code a "+
			"node boots. The api is starting anyway so this control plane stays reachable and fixable; "+
			"bundle upload and staging refuse until the trust root is in place.", v.UnavailableReason())
	}
	return v
}

// wireMesh selects, builds, and bootstraps the mesh backend, returning the
// client, the supervisor, and the effective login-server URL agents should
// dial. The choice (RASPUTIN_MESH_BACKEND, default "auto"):
//
//	auto      — external Headscale creds set → real client against them
//	            (noop supervisor); else Docker present → self-hosted (the
//	            supervisor brings up Headscale and mints its own admin key,
//	            real client against it); else → file-backed mock (CI/dev).
//	mock      — force the file-backed mock + noop supervisor.
//	headscale — force real; requires external creds OR Docker (errors if
//	            neither is available, rather than silently mocking).
//
// "Self-hosted" is the production path and needs no operator input: the
// supervisor owns the container so it can mint the very API key the client
// needs (see DockerSupervisor.MintSessionAPIKey). This is why mesh can't be
// provisioned via a seed env var — the Headscale instance doesn't exist
// until first boot — and why autodetect-on-Docker is the right default.
//
// wireMesh is non-blocking: the self-hosted path returns a placeholder client
// plus a `bootstrap` closure that the mesh.Service runs in the BACKGROUND
// (container up → key mint → real client). The api must boot and serve
// /healthz regardless of whether Headscale can start — a control plane gated
// on a container coming up is fragile.
type meshWiring struct {
	client    mesh.Client
	sup       mesh.Supervisor
	login     string
	caPEM     []byte                                     // shipped to nodes so tailscaled trusts the Headscale leaf
	bootstrap func(context.Context) (mesh.Client, error) // nil for eager (mock/external) modes
}

func wireMesh(stateDir string, meshCA *mesh.MeshCA, defaultLogin string) (meshWiring, error) {
	backend := strings.ToLower(envOr("RASPUTIN_MESH_BACKEND", "auto"))
	extURL := os.Getenv("RASPUTIN_HEADSCALE_URL")
	extKey := os.Getenv("RASPUTIN_HEADSCALE_API_KEY")
	hasExternal := extURL != "" && extKey != ""
	dockerWanted := dockerAvailable() ||
		strings.ToLower(envOr("RASPUTIN_HEADSCALE_SUPERVISOR", "")) == "docker"

	switch backend {
	case "mock":
		return wireMockMesh(stateDir, defaultLogin)
	case "auto", "":
		if hasExternal {
			return wireExternalMesh(stateDir, meshCA, defaultLogin, extURL, extKey)
		}
		if dockerWanted {
			return wireSelfHostedMesh(stateDir, meshCA, defaultLogin)
		}
		// ⚠️ THIS USED TO FALL THROUGH TO THE MOCK, and that is the same
		// class of bug as the 2026-09-01 storage incident: a missing
		// prerequisite silently became a confident, fabricated answer. The
		// mock mesh mints keys and the enroll saga invents a 100.64.0.x
		// tailnet address per node, which /api/mesh/devices then serves as
		// though the node were really on the tailnet.
		//
		// `auto` means "detect a real backend", so when there is no real
		// backend to detect the honest result is none. The api still boots
		// and serves everything else; mesh verbs fail with this reason.
		// Dev and CI ask for the mock by name.
		return wireUnavailableMesh(defaultLogin,
			"no external Headscale is configured (RASPUTIN_HEADSCALE_URL + "+
				"RASPUTIN_HEADSCALE_API_KEY) and the docker CLI needed for the "+
				"self-hosted one is not on PATH")
	case "headscale":
		if hasExternal {
			return wireExternalMesh(stateDir, meshCA, defaultLogin, extURL, extKey)
		}
		if dockerWanted {
			return wireSelfHostedMesh(stateDir, meshCA, defaultLogin)
		}
		return meshWiring{}, errors.New("RASPUTIN_MESH_BACKEND=headscale requires either RASPUTIN_HEADSCALE_URL+RASPUTIN_HEADSCALE_API_KEY (external) or the docker CLI on PATH (self-hosted)")
	default:
		return meshWiring{}, errors.New("unknown RASPUTIN_MESH_BACKEND: " + backend)
	}
}

// wireUnavailableMesh is what `auto` returns when it finds no real backend. The
// api boots normally; every mesh verb refuses with reason. See
// mesh.UnavailableClient for why this is not a fallback to the mock.
func wireUnavailableMesh(defaultLogin, reason string) (meshWiring, error) {
	log.Printf("rasputin-api: ⚠️  mesh backend UNAVAILABLE: %s. No mock was substituted — a mock "+
		"mesh reports nodes as enrolled with invented tailnet addresses. The api is starting "+
		"anyway; mesh enroll/list will fail with this reason until a real backend is configured, "+
		"or set RASPUTIN_MESH_BACKEND=mock explicitly if this is a dev box.", reason)
	return meshWiring{
		client: mesh.NewUnavailableClient(reason),
		sup:    mesh.NewNoopSupervisor(),
		login:  defaultLogin,
	}, nil
}

// wireMockMesh is the dev/CI fixture: file-backed client, no supervisor. Only
// ever reached by an explicit RASPUTIN_MESH_BACKEND=mock — never autodetected.
func wireMockMesh(stateDir, defaultLogin string) (meshWiring, error) {
	log.Printf("rasputin-api: mesh backend = mock (file-backed at %s) — EXPLICITLY REQUESTED; "+
		"enrollments and tailnet addresses reported from here are simulated", stateDir)
	c, err := mesh.NewMockClient(stateDir)
	if err != nil {
		return meshWiring{}, err
	}
	return meshWiring{client: c, sup: mesh.NewNoopSupervisor(), login: defaultLogin}, nil
}

// wireExternalMesh talks to a Headscale the operator runs themselves. We
// trust the system pool unless RASPUTIN_HEADSCALE_CA_FILE points at a PEM
// bundle (e.g. their internal CA) — in which case nodes need that CA too, so
// it is APPENDED to the Mesh CA in the bundle the enroll command ships
// (mesh.NodeTrustBundle; geekdojo/geekdojo-brain#506). The Mesh CA goes to
// every node whoever runs Headscale: it also signs the api's own HTTPS leaf
// and the app leaves. The container lifecycle is theirs (noop supervisor)
// unless they explicitly asked us to drive it. Eager: the client is
// constructed up front (EnsureUser still runs in the background Start).
func wireExternalMesh(stateDir string, meshCA *mesh.MeshCA, defaultLogin, url, key string) (meshWiring, error) {
	cfg := mesh.RealClientConfig{BaseURL: url, APIKey: key}
	var operatorCA []byte
	if caFile := os.Getenv("RASPUTIN_HEADSCALE_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return meshWiring{}, errors.New("read RASPUTIN_HEADSCALE_CA_FILE: " + err.Error())
		}
		// One helper for both backends. Read once: the file the api trusts
		// and the CA the nodes are shipped are the same bytes, and a file
		// that cannot be read fails the start rather than quietly shipping
		// nodes a CA the api itself does not trust.
		tlsCfg, cerr := mesh.CATLSConfig(pem, "RASPUTIN_HEADSCALE_CA_FILE="+caFile)
		if cerr != nil {
			return meshWiring{}, cerr
		}
		cfg.TLSConfig = tlsCfg
		operatorCA = pem
	}
	c, err := mesh.NewRealClient(cfg)
	if err != nil {
		return meshWiring{}, err
	}
	var sup mesh.Supervisor = mesh.NewNoopSupervisor()
	if strings.ToLower(envOr("RASPUTIN_HEADSCALE_SUPERVISOR", "noop")) == "docker" {
		ds, derr := newDockerSupervisor(stateDir, meshCA)
		if derr != nil {
			return meshWiring{}, derr
		}
		sup = ds
	}
	caPEM := mesh.NodeTrustBundle(meshCA.CertPEM, operatorCA)
	bundle := "mesh-ca"
	if len(operatorCA) > 0 {
		bundle = "mesh-ca+operator-ca"
	}
	// %q on the url: it is this process's own RASPUTIN_HEADSCALE_URL, but
	// quoting it means not even a hand-edited node.env could forge a second
	// log line. bundle is one of two literals.
	log.Printf("rasputin-api: mesh backend = headscale (external, url=%q, node trust bundle=%s)", url, bundle)
	return meshWiring{client: c, sup: sup, login: url, caPEM: caPEM}, nil
}

// wireSelfHostedMesh is the production path. It builds the supervisor cheaply
// (no container work) and returns a placeholder client plus a bootstrap
// closure that mesh.Service runs in the background: bring the container up,
// mint this process's in-memory admin key, and point a real client at the local HTTPS
// endpoint trusting the per-installation Mesh CA. Ships meshCA.CertPEM to
// nodes so tailscaled trusts the same leaf. Nothing here blocks api boot.
func wireSelfHostedMesh(stateDir string, meshCA *mesh.MeshCA, defaultLogin string) (meshWiring, error) {
	sup, err := newDockerSupervisor(stateDir, meshCA)
	if err != nil {
		return meshWiring{}, err
	}
	// The same helper the external path uses; here the root that signs the
	// Headscale leaf is this installation's Mesh CA (#506).
	tlsCfg, err := mesh.CATLSConfig(meshCA.CertPEM, "the Mesh CA")
	if err != nil {
		return meshWiring{}, err
	}
	url := sup.ServerURL() // resolved at construction; no container needed
	bootstrap := func(ctx context.Context) (mesh.Client, error) {
		if err := sup.Start(ctx); err != nil {
			return nil, fmt.Errorf("start headscale container: %w", err)
		}
		// A fresh admin key per api start, held only in memory; minting it
		// expires the one the previous process held. A 401 re-mints.
		key, err := sup.MintSessionAPIKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("bootstrap headscale api key: %w", err)
		}
		return mesh.NewRealClient(mesh.RealClientConfig{
			BaseURL:       url,
			APIKey:        key,
			RefreshAPIKey: sup.MintSessionAPIKey,
			TLSConfig:     tlsCfg,
		})
	}
	log.Printf("rasputin-api: mesh backend = headscale (self-hosted, url=%s, tls=mesh-ca; bringing up in background)", url)
	return meshWiring{
		client:    mesh.NewNotReadyClient("headscale"),
		sup:       sup,
		login:     url,
		caPEM:     mesh.NodeTrustBundle(meshCA.CertPEM),
		bootstrap: bootstrap,
	}, nil
}

// newDockerSupervisor builds a DockerSupervisor from env overrides + the Mesh
// CA (which switches it into HTTPS mode with a per-installation leaf).
func newDockerSupervisor(stateDir string, meshCA *mesh.MeshCA) (*mesh.DockerSupervisor, error) {
	cfg := mesh.DockerSupervisorConfig{
		StateDir:   filepath.Join(stateDir, "headscale"),
		Image:      os.Getenv("RASPUTIN_HEADSCALE_IMAGE"),
		ListenAddr: os.Getenv("RASPUTIN_HEADSCALE_LISTEN_ADDR"),
		// The URL agents dial for `tailscale up --login-server`, and the host
		// the Headscale leaf is minted for. Derived from the cluster name on a
		// provisioned node; "" in dev, where the supervisor falls back to
		// resolveServerHost(ListenAddr) exactly as before.
		//
		// NOTE this is the ONLY place RASPUTIN_HEADSCALE_URL gets a default.
		// Its other read (wireMesh) uses the variable's presence to select an
		// EXTERNAL Headscale, so defaulting it there would make every
		// self-hosted appliance believe it had external creds.
		ServerURL:     envOr("RASPUTIN_HEADSCALE_URL", applianceOr(func(h string) string { return "https://" + h + ":18080" }, "")),
		ContainerName: os.Getenv("RASPUTIN_HEADSCALE_CONTAINER"),
		// Bare cluster id → the MagicDNS base domain "<cluster-id>.internal".
		ClusterID: strings.TrimSpace(os.Getenv("RASPUTIN_CLUSTER_ID")),
		MeshCA:    meshCA,
	}
	log.Printf("rasputin-api: mesh supervisor = docker (state=%s, tls=%v)",
		cfg.StateDir, cfg.MeshCA != nil)
	return mesh.NewDockerSupervisor(cfg)
}

// dockerBinAvailable reports whether the named docker CLI is on PATH.
// Split out from dockerAvailable so obs can preflight against its OWN
// configured binary: dockerAvailable keys off RASPUTIN_HEADSCALE_DOCKER_BIN,
// and an obs preflight that consulted a mesh-namespaced variable would be
// quietly wrong for anyone who set only one of them.
func dockerBinAvailable(bin string) bool {
	if bin == "" {
		bin = "docker"
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// dockerAvailable reports whether a docker CLI is on PATH — mirrors the
// agent's autodetect for its docker/rauc/uci/tailscale backends.
func dockerAvailable() bool {
	return dockerBinAvailable(envOr("RASPUTIN_HEADSCALE_DOCKER_BIN", "docker"))
}

// obsDockerBin is the container runtime obs shells out to. Its own env var,
// defaulted to "docker".
func obsDockerBin() string { return envOr("RASPUTIN_OBS_DOCKER_BIN", "docker") }

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// mustWireObs constructs the Tier 2 observability stack — supervisor +
// VictoriaMetrics fan-out sink + read-only status surface. The supervisor is
// built UNCONDITIONALLY; whether the stack actually runs is the operator's
// stored `obs.enabled` setting, read through the `enabled` closure.
//
// That unconditional construction is the whole point of Slice 1.6. Before
// it, an unset RASPUTIN_OBS_ENABLED returned a nil supervisor — so there was
// no object to Start() later and the only way to turn observability on was
// to restart the process with a different environment. On an appliance
// (read-only rootfs, no shell, no SSH server) that is not a thing an
// operator can do, which meant a complete Tier 2 stack shipped unreachable.
// Constructing always costs a struct; it buys a UI toggle.
//
// Building the supervisor does no I/O beyond an mkdir — no Docker contact,
// no containers — so this is cheap even when the operator never opts in.
//
// Why "must" — the failure modes here (mkdir, supervisor construction) are
// configuration / system issues the operator needs to fix before the api can
// usefully run with obs on. We don't paper over them by silently disabling
// obs; that would mask the real problem. Note the *start* failure path is
// deliberately not fatal: a stack that won't come up must not take the api
// down with it.
//
// Env vars (all now *defaults* — the operator's stored choice wins; see
// seedObsEnabled):
//
//	RASPUTIN_OBS_ENABLED       — seeds obs.enabled on first boot only.
//	RASPUTIN_OBS_DOCKER_BIN    — container runtime binary. Default "docker".
//	RASPUTIN_OBS_STATE_DIR     — host dir for compose + VM data.
//	                              Defaults to <dataDir>/obs.
//	RASPUTIN_OBS_VM_IMAGE      — VictoriaMetrics image override.
//	RASPUTIN_OBS_VM_LISTEN     — host bind for VM's HTTP listener.
//	                              Defaults to 127.0.0.1:8428.
//	RASPUTIN_OBS_VM_RETENTION  — VM -retentionPeriod flag. Default "1y".
//	RASPUTIN_OBS_VM_MIN_FREE_DISK — free space VM reserves on the partition
//	                              before refusing writes. Default "2GB".
//	RASPUTIN_OBS_LOKI_RETENTION — how long logs are kept. Default "720h" (30d).
//
// RASPUTIN_OBS_ALLOY_LISTEN is GONE. Alloy's debug server is no longer
// published to the host at all — nothing read it, and it has no
// authentication (geekdojo-brain#452). RASPUTIN_OBS_GRAFANA_LISTEN survives
// only for non-Linux developer hosts; on Linux Grafana serves on a unix
// socket and has no TCP listener to bind (geekdojo-brain#453).
//
// Side effect: when the stored setting says on, this starts the stack in the
// background and calls metricsSvc.SetSink so every received MetricsEvt fans
// out to VM after the SQLite insert.
func mustWireObs(ctx context.Context, dataDir, selfNodeID string, metricsSvc *metrics.Service, idsLogDir string, enabled obs.EnabledFn) (*obs.DockerComposeSupervisor, *obs.VMSink, *obs.Status) {
	stateDir := envOr("RASPUTIN_OBS_STATE_DIR", filepath.Join(dataDir, "obs"))
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		log.Fatalf("rasputin-api: obs state dir: %v", err)
	}
	sup, err := obs.NewDockerComposeSupervisor(obs.DockerComposeSupervisorConfig{
		StateDir:           stateDir,
		ControlPlaneNodeID: selfNodeID,
		DockerBin:          obsDockerBin(),
		VMImage:            os.Getenv("RASPUTIN_OBS_VM_IMAGE"),
		VMListenAddr:       os.Getenv("RASPUTIN_OBS_VM_LISTEN"),
		VMRetention:        os.Getenv("RASPUTIN_OBS_VM_RETENTION"),
		VMMinFreeDiskSpace: os.Getenv("RASPUTIN_OBS_VM_MIN_FREE_DISK"),
		AlloyImage:         os.Getenv("RASPUTIN_OBS_ALLOY_IMAGE"),
		EnableCadvisor:     envBoolPtr("RASPUTIN_OBS_ALLOY_CADVISOR"),
		LokiImage:          os.Getenv("RASPUTIN_OBS_LOKI_IMAGE"),
		LokiListenAddr:     os.Getenv("RASPUTIN_OBS_LOKI_LISTEN"),
		LokiRetention:      os.Getenv("RASPUTIN_OBS_LOKI_RETENTION"),
		EnableLoki:         envBoolPtr("RASPUTIN_OBS_LOKI"),
		GrafanaImage:       os.Getenv("RASPUTIN_OBS_GRAFANA_IMAGE"),
		// RASPUTIN_OBS_GRAFANA_LISTEN only has an effect on a non-Linux
		// developer host, where Grafana cannot bind a unix socket. On a
		// controlplane there is no Grafana TCP listener to move.
		GrafanaListenAddr: os.Getenv("RASPUTIN_OBS_GRAFANA_LISTEN"),
		EnableGrafana:     envBoolPtr("RASPUTIN_OBS_GRAFANA"),
		VMAlertImage:      os.Getenv("RASPUTIN_OBS_VMALERT_IMAGE"),
		EnableVMAlert:     envBoolPtr("RASPUTIN_OBS_VMALERT"),
		// IDS log dir mounted into Alloy at /var/log/rasputin so
		// loki.source.file can ship the api's alerts.jsonl to Loki.
		// Same path the api's ids.Writer just opened a few lines above
		// — passed through as a string both ends use literally so a
		// rename in one place trips a build error not a runtime miss.
		IDSLogDir:     idsLogDir,
		EnableIDSPipe: envBoolPtr("RASPUTIN_OBS_IDS_PIPE"),
	})
	if err != nil {
		log.Fatalf("rasputin-api: obs supervisor: %v", err)
	}
	sink, err := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	if err != nil {
		log.Fatalf("rasputin-api: obs sink: %v", err)
	}
	// LogsClient wraps the same supervisor — when Loki is on, LokiBaseURL()
	// is non-empty and queries proxy through; when off, the client returns
	// a clean "Loki not configured" error.
	logs, err := obs.NewLogsClient(obs.LogsClientConfig{Supervisor: sup})
	if err != nil {
		log.Fatalf("rasputin-api: obs logs client: %v", err)
	}
	status := obs.NewStatus(sup, sink, logs)
	status.SetEnabled(enabled)

	on, err := enabled(ctx)
	if err != nil {
		log.Fatalf("rasputin-api: read obs setting: %v", err)
	}
	if !on {
		// Constructed but idle. No sink is installed: VMSink.Write errors
		// when the stack is down and metrics.Service logs every failure, so
		// an always-installed sink would spam the log every 10s per node.
		// obs.enable installs it as its last step.
		log.Printf("rasputin-api: obs off (state=%s) — turn it on from Settings", stateDir)
		return sup, sink, status
	}
	log.Printf("rasputin-api: obs supervisor = docker (state=%s, vm=%s)",
		stateDir, sup.VMBaseURL())
	// Start asynchronously so first-boot doesn't block the api's HTTP
	// listener behind a slow `docker pull`. The supervisor's health
	// probe drives the sink's "is it worth trying to write?" check; if
	// VM never comes up, writes simply fail-fast.
	go func() {
		startCtx, startCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer startCancel()
		if err := sup.Start(startCtx); err != nil {
			log.Printf("rasputin-api: obs supervisor start: %v", err)
		} else {
			log.Printf("rasputin-api: obs supervisor up; VM at %s", sup.VMBaseURL())
		}
	}()
	metricsSvc.SetSink(sink)
	return sup, sink, status
}

// seedObsEnabled captures RASPUTIN_OBS_ENABLED as the initial value of the
// obs.enabled setting — but only when the setting has NEVER been set, so an
// explicit operator choice sticks. Mirrors SeedOperatorSSHKeysFromFile.
//
// This is what keeps the env var from becoming a rival source of truth. A
// dev box that exports RASPUTIN_OBS_ENABLED=1 still comes up with obs on;
// but once anyone uses the UI toggle, the stored choice is authoritative and
// the env var is never consulted again. Without the "only if unset" guard,
// every restart would silently undo the operator's last click.
// seedBMCHostNode writes the env-derived BMC host into settings once —
// only if the operator has never chosen (IsSet). Same recipe as
// seedObsEnabled: env seeds first boot, the Settings choice wins
// permanently (bmc-settings.md S-5).
func seedBMCHostNode(ctx context.Context, store *setup.Store, hostNodeID string) {
	if hostNodeID == "" {
		return
	}
	set, err := store.IsSet(ctx, setup.KeyBMCHostNode)
	if err != nil {
		log.Printf("rasputin-api: read %s: %v", setup.KeyBMCHostNode, err)
		return
	}
	if set {
		return
	}
	if err := store.Set(ctx, setup.KeyBMCHostNode, hostNodeID); err != nil {
		log.Printf("rasputin-api: seed %s: %v", setup.KeyBMCHostNode, err)
		return
	}
	log.Printf("rasputin-api: seeded %s=%s from env (operator choice wins from here on)", setup.KeyBMCHostNode, hostNodeID)
}

func seedObsEnabled(ctx context.Context, store *setup.Store) {
	set, err := store.IsSet(ctx, setup.KeyObsEnabled)
	if err != nil {
		log.Printf("rasputin-api: read obs.enabled: %v", err)
		return
	}
	if set {
		return
	}
	raw, ok := os.LookupEnv("RASPUTIN_OBS_ENABLED")
	if !ok {
		return // stay unset; the default (off) applies and a later boot can seed
	}
	on := setup.ParseBool(raw)
	if err := store.SetBool(ctx, setup.KeyObsEnabled, on); err != nil {
		log.Printf("rasputin-api: seed obs.enabled: %v", err)
		return
	}
	log.Printf("rasputin-api: seeded obs.enabled=%v from RASPUTIN_OBS_ENABLED (operator choice wins from here on)", on)
}

// parseDurationOr parses s as a duration; on parse error or zero/negative,
// returns def. Lets env-var overrides degrade safely.
func parseDurationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// parseIntOr reads a positive integer from an env value, or returns def.
func parseIntOr(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// restoreExitCode is what the process exits with after preparing a restore,
// so the unit's Restart= policy — on-failure or always — starts it again onto
// the restored identity. 75 is EX_TEMPFAIL: "try again", which is exactly
// the instruction.
const restoreExitCode = 75

var restoreExitRequested atomic.Bool

// requestRestoreExit marks that this process should exit non-zero once its
// ordinary shutdown has run. Called by the restore handler's restart hook.
func requestRestoreExit() { restoreExitRequested.Store(true) }

// restoreExit is deferred FIRST in main, so it runs LAST — after every store
// has closed and every subsystem has stopped — and turns a clean shutdown
// into the non-zero exit a restart needs. On every other run it does
// nothing.
func restoreExit() {
	if restoreExitRequested.Load() {
		log.Printf("rasputin-api: exiting %d so the unit restarts this api onto the restored identity", restoreExitCode)
		os.Exit(restoreExitCode)
	}
}

// busTLSStartMode reads the bus TLS mode before the bus starts — which is
// before the rest of the stores open, so it opens the settings store, and the
// inventory store the facts come from, on its own for the one read each.
//
// tlsAvailable is whether the bus key loaded. A settings store that will not
// open is itself a fault: it resolves through the facts like any other
// unreadable mode, never to offer (bustls.ResolveStartMode).
func busTLSStartMode(ctx context.Context, dbPath string, tlsAvailable bool) bustls.StartMode {
	facts := busTLSStartFacts(ctx, dbPath, tlsAvailable)
	if os.Getenv(bustls.EnvMode) != "" {
		return bustls.ResolveStartMode(ctx, nil, facts)
	}
	st, err := setup.OpenStore(ctx, dbPath)
	if err != nil {
		return bustls.ResolveStartMode(ctx, failingSettings{err}, facts)
	}
	defer func() { _ = st.Close() }()
	return bustls.ResolveStartMode(ctx, st, facts)
}

// busTLSStartFacts reads inventory for the two facts a derived mode rests on:
// how many nodes are enrolled, and whether every one of them reported bus TLS.
//
// An inventory that will not open answers "nodes are enrolled and not all of
// them are on TLS", which is the conservative reading: it derives migrate, the
// rung that keeps a fleet reachable, rather than require on a fleet nobody
// could look at.
func busTLSStartFacts(ctx context.Context, dbPath string, tlsAvailable bool) bustls.StartFacts {
	unknown := bustls.StartFacts{TLSAvailable: tlsAvailable, Enrolled: 1, AllReportedTLS: false}
	inv, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		log.Printf("rasputin-api: bus TLS mode: read inventory: %v — assuming a fleet that is not all on TLS", err)
		return unknown
	}
	defer func() { _ = inv.Close() }()
	nodes, err := inv.List(ctx)
	if err != nil {
		log.Printf("rasputin-api: bus TLS mode: list inventory: %v — assuming a fleet that is not all on TLS", err)
		return unknown
	}
	return bustls.FactsFromNodes(tlsAvailable, nodes)
}

// failingSettings stands in for a settings store that would not open, so the
// one read reports the open error the way an unreadable setting reports its
// own. It is never written to.
type failingSettings struct{ err error }

func (f failingSettings) Get(context.Context, string) (string, error) {
	return "", fmt.Errorf("open settings: %w", f.err)
}
func (f failingSettings) Set(context.Context, string, string) error {
	return fmt.Errorf("open settings: %w", f.err)
}

// recordBusTLSMode persists a derived mode, opening the settings store on its
// own for the one write — this runs before the rest of the stores are open.
func recordBusTLSMode(ctx context.Context, dbPath string, mode bustls.Mode) error {
	st, err := setup.OpenStore(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open settings: %w", err)
	}
	defer func() { _ = st.Close() }()
	return st.Set(ctx, bustls.SettingKey, string(mode))
}

// removeAppLeafDir removes one app's leaf directory under root. It refuses an
// id that is not shaped like an app id, and any path that does not clean to a
// direct child of root, so a caller can only ever remove a single app's
// directory, whatever string it was handed.
func removeAppLeafDir(root, appID string) error {
	if !proto.ValidAppID(appID) {
		return fmt.Errorf("remove app leaf: %q is not an app id", appID)
	}
	root = filepath.Clean(root)
	dir := filepath.Join(root, appID)
	if filepath.Dir(dir) != root || filepath.Base(dir) != appID {
		return fmt.Errorf("remove app leaf: %q is not a direct child of %q", dir, root)
	}
	return os.RemoveAll(dir)
}
