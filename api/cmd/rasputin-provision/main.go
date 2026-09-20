// Command rasputin-provision generates a cluster "matched set": one bus join
// token per node, bound to that node's id, written into each node's seed, plus
// the controlplane's preseed (token hashes + bindings) so the bus accepts those
// nodes on first boot with enforcement on.
//
// It is the offline half of the token-provisioning pipeline
// (design/os-images/token-provisioning-pipeline.md). It shares
// busauth.GenerateToken/HashToken with the api so the minter and the validator
// can never disagree on the token format. It mints NO live state and talks to no
// controlplane — it just emits files a human (or, later, a web flow) hands to
// fulfillment.
//
// Usage:
//
//	rasputin-provision \
//	  --cluster-id home1 \
//	  --node controlplane:home1-cp \
//	  --node firewall:home1-fw \
//	  --node compute:home1-n1 --node compute \
//	  [--nats-url nats://<cluster-id>.local:4222] [--out ./out/home1] \
//	  [--ssh-authorized-key-file ~/.ssh/id_ed25519.pub]
//
// A --node value is "role[:node-id]". When the id is omitted it's auto-assigned
// as "<cluster-id>-<role><seq>". Roles: controlplane | firewall | compute | storage.
//
// Every matched set also gets its own bus key (geekdojo/geekdojo-brain#448,
// docs/bus-tls-contract.md): the controlplane's seed carries the private key as
// RASPUTIN_BUS_KEY, and EVERY seed — the controlplane's included, for its own
// co-located agent — carries RASPUTIN_BUS_PIN, the hash nodes verify the bus
// server's TLS key against. The key exists only in the controlplane seed;
// firstboot moves it to /var/lib/rasputin/bus/bus.key and scrubs the seed.
//
// --ssh-authorized-key / --ssh-authorized-key-file put the OPERATOR's public
// key into every node's seed (RASPUTIN_SSH_AUTHORIZED_KEY, double-quoted — the
// seed is sourced by sh). Images bake no SSH key at all (pre-GA vendor-key
// removal, 2026-07-09), so this seed field is the only way to get network SSH
// on a node; omit it and the cluster is console/UI-only, which is valid.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// defaultNATSURLFor is the bus address baked into every non-controlplane seed:
// the cluster's own mDNS name (ADR-0003), not a shared literal. With the
// default cluster id "rasputin" this yields nats://rasputin.local:4222 —
// exactly the constant it replaces, which is why no existing matched set
// changes shape.
//
// It cannot be a flag default: flag defaults are evaluated before parsing, so
// --cluster-id is not known yet. generate() applies it after validating the id.
func defaultNATSURLFor(clusterID string) string {
	return "nats://" + clusterID + ".local:4222"
}

// loopbackNATSURL is what the controlplane's own co-located agent dials: its
// own box, with no dependency on the cluster name resolving. Loopback earns it
// no trust (geekdojo-brain#140) — it authenticates with the token its api
// mints at start (proto.BusAgentTokenPath), which is why its seed carries none.
// See token-provisioning-pipeline.md.
const loopbackNATSURL = "nats://127.0.0.1:4222"

type nodeSpec struct {
	Role string
	ID   string
}

type nodeList []nodeSpec

func (n *nodeList) String() string { return fmt.Sprintf("%v", *n) }

func (n *nodeList) Set(v string) error {
	role, id, _ := strings.Cut(v, ":")
	role = strings.TrimSpace(role)
	id = strings.TrimSpace(id)
	switch role {
	case "controlplane", "firewall", "compute", "storage":
	default:
		return fmt.Errorf("unknown role %q (want controlplane|firewall|compute|storage)", role)
	}
	*n = append(*n, nodeSpec{Role: role, ID: id})
	return nil
}

// manifestNode is the audit record for one node — never carries a plaintext token.
type manifestNode struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	SeedFile  string `json:"seedFile"`
	TokenHash string `json:"tokenHash,omitempty"` // omitted for the controlplane (no token)
	Bound     bool   `json:"bound"`
}

type manifest struct {
	ClusterID   string         `json:"clusterId"`
	GeneratedAt string         `json:"generatedAt"`
	NATSURL     string         `json:"natsUrl"`
	Enforce     bool           `json:"enforce"`
	SSHKey      bool           `json:"sshAuthorizedKey"` // whether seeds carry an operator SSH key (never the key itself)
	Nodes       []manifestNode `json:"nodes"`
	PreseedFile string         `json:"preseedFile"`
	BusPin      string         `json:"busPin"` // the pin every seed carries (public); the key is only in the controlplane seed
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "rasputin-provision:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		clusterID  = flag.String("cluster-id", "", "cluster id (required)")
		natsURL    = flag.String("nats-url", "", "control-plane NATS URL baked into non-controlplane seeds (default: nats://<cluster-id>.local:4222)")
		outDir     = flag.String("out", "", "output directory (default ./out/<cluster-id>)")
		enforce    = flag.Bool("enforce", true, "bake RASPUTIN_BUS_AUTH=enforce into the controlplane seed (a matched set ships enforced)")
		sshKey     = flag.String("ssh-authorized-key", "", "operator SSH public key baked into every seed (one key line, e.g. \"ssh-ed25519 AAAA... you@laptop\")")
		sshKeyFile = flag.String("ssh-authorized-key-file", "", "read the operator SSH public key from a file (e.g. ~/.ssh/id_ed25519.pub); mutually exclusive with --ssh-authorized-key")
		nodes      nodeList
	)
	flag.Var(&nodes, "node", "node as role[:node-id] (repeatable)")
	flag.Parse()

	key, err := resolveSSHKey(*sshKey, *sshKeyFile)
	if err != nil {
		return err
	}

	// Normalize BEFORE the output path is derived from it. generate() would
	// normalize anyway, but by then `out/<cluster-id>` and the summary line
	// have already been built from the raw flag — so `--cluster-id Home1` would
	// write a directory named "Home1" holding a manifest that says "home1", and
	// tell the operator they had provisioned "Home1". A mismatch like that is
	// how someone later re-runs with the wrong name and gets a second cluster.
	normalized, err := normalizeDNSLabel("cluster id", *clusterID)
	if err != nil {
		return err
	}

	dir := *outDir
	if dir == "" {
		dir = filepath.Join("out", normalized)
	}
	man, err := generate(normalized, *natsURL, dir, nodes, *enforce, key)
	if err != nil {
		return err
	}

	fmt.Printf("provisioned %d nodes for cluster %q → %s\n", len(man.Nodes), man.ClusterID, dir)
	fmt.Printf("  • per-node seeds (the tokens live ONLY here — treat as secrets)\n")
	fmt.Printf("  • %s → the controlplane's seed (preload via firstboot)\n", man.PreseedFile)
	fmt.Printf("  • manifest.json → audit record (no plaintext)\n")
	fmt.Printf("  • every seed pins the bus key %s; the controlplane seed carries the bus PRIVATE key (secret — firstboot moves it off the card)\n", man.BusPin)
	if man.SSHKey {
		fmt.Printf("  • every seed carries the operator SSH key (key-only network SSH enabled)\n")
	} else {
		fmt.Printf("  • NO SSH key in the seeds — images bake none, so the cluster is console/UI-only; pass --ssh-authorized-key[-file] for network SSH\n")
	}
	return nil
}

// resolveSSHKey merges the two --ssh-authorized-key* flags into one validated
// key line ("" = no key, a valid choice: console/UI-only cluster).
//
// The rule itself is setup.ValidOperatorSSHKey — the ONE operator-SSH-key
// validator (methodology §5.1, geekdojo/geekdojo-brain#545). This function
// used to carry its own copy, the api carried a second, and the UI a third,
// each with a comment asking the next reader to keep all three in sync. A key
// this tool accepts and the wizard refuses (or the reverse) is a cluster
// provisioned two ways from one keyboard, so there is now one rule and one set
// of vectors it is tested against.
func resolveSSHKey(literal, file string) (string, error) {
	literal = strings.TrimSpace(literal)
	if literal != "" && file != "" {
		return "", fmt.Errorf("--ssh-authorized-key and --ssh-authorized-key-file are mutually exclusive")
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read ssh key file: %w", err)
		}
		literal = strings.TrimSpace(string(b))
	}
	if literal == "" {
		return "", nil
	}
	if strings.ContainsAny(literal, "\n\r") {
		return "", fmt.Errorf("ssh authorized key must be a single key line (got multiple lines)")
	}
	if !setup.ValidOperatorSSHKey(literal) {
		return "", fmt.Errorf("value doesn't look like an OpenSSH public key (want e.g. \"ssh-ed25519 AAAA... comment\"): %w", setup.ErrInvalidSSHKey)
	}
	return literal, nil
}

// normalizeDNSLabel lowercases and validates a value that becomes a DNS label.
//
// Both ids this tool assigns end up as a machine's mDNS hostname: the cluster
// id becomes the controlplane's (ADR-0003), and a node id becomes every other
// node's. From there the cluster id is also the CN/SAN of the api's TLS leaf,
// the WebAuthn RP ID, and the host every seeded NATS URL dials.
//
// Validating HERE is the point: rasputin-hostname.sh also checks, but it runs
// at boot on a headless box and can only fall back to "rasputin" and log. The
// operator then sees a cluster that silently kept the wrong name, three layers
// away from the typo. Rejecting at the keyboard costs one error message.
//
// Lowercased rather than rejected — DNS labels are case-insensitive, and the
// seed consumers (rasputin-os firstboot and the firewall's apply-seed, both via
// rasputin_label_canon) trim and lowercase the seed's id the same way before
// validating it. Neither ever derives a node id: every seed must carry
// RASPUTIN_NODE_ID (rasputin-os#75, rasputin-openwrt-firewall#51), so the id
// this tool writes is the node's id. Normalizing here means the seed carries
// the canonical form, so every downstream consumer agrees on it.
func normalizeDNSLabel(kind, v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", fmt.Errorf("%s is required", kind)
	}
	if len(v) > 63 {
		return "", fmt.Errorf("%s %q is %d characters; a DNS label allows at most 63", kind, v, len(v))
	}
	if strings.HasPrefix(v, "-") || strings.HasSuffix(v, "-") {
		return "", fmt.Errorf("%s %q must not start or end with a hyphen", kind, v)
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			hint := ""
			if r == '.' {
				// Worth naming explicitly: a dotted value looks reasonable and
				// is the one failure ADR-0003 calls out — systemd-resolved
				// publishes only a single-label <hostname>.local, so
				// "home.lab" would produce a name nothing can advertise.
				hint = " (a dot would make it a multi-label name, which mDNS cannot publish)"
			}
			return "", fmt.Errorf("%s %q contains %q; only a-z, 0-9 and - are allowed%s", kind, v, string(r), hint)
		}
	}
	return v, nil
}

// generate assigns ids, validates the set, and writes all artifacts into dir.
// Returns the manifest. Pure enough to unit-test end-to-end. sshKey ("" = none)
// is the operator's public key, already validated by resolveSSHKey.
func generate(clusterID, natsURL, dir string, nodes nodeList, enforce bool, sshKey string) (manifest, error) {
	clusterID, err := normalizeDNSLabel("cluster id", clusterID)
	if err != nil {
		return manifest{}, err
	}
	if len(nodes) == 0 {
		return manifest{}, fmt.Errorf("at least one node is required")
	}
	// Derived here, not at the flag, because the cluster id is only known after
	// parsing — and only trustworthy after the check above.
	if natsURL == "" {
		natsURL = defaultNATSURLFor(clusterID)
	}

	// Assign ids for nodes given by role only, and check uniqueness + single
	// controlplane.
	seq := map[string]int{}
	seen := map[string]bool{}
	cpCount := 0
	for i := range nodes {
		if nodes[i].Role == "controlplane" {
			cpCount++
		}
		if nodes[i].ID == "" {
			seq[nodes[i].Role]++
			nodes[i].ID = fmt.Sprintf("%s-%s%d", clusterID, nodes[i].Role, seq[nodes[i].Role])
		}
		// A node id becomes that node's hostname, so it faces the same
		// constraint as the cluster id. Auto-assigned ids are valid by
		// construction; an operator-supplied one is not.
		nodes[i].ID, err = normalizeDNSLabel("node id", nodes[i].ID)
		if err != nil {
			return manifest{}, err
		}
		if seen[nodes[i].ID] {
			return manifest{}, fmt.Errorf("duplicate node id %q", nodes[i].ID)
		}
		seen[nodes[i].ID] = true
	}
	if cpCount != 1 {
		return manifest{}, fmt.Errorf("a matched set needs exactly one controlplane node, got %d", cpCount)
	}

	// 0700 when this creates it: the directory receives every node's seed. An
	// existing directory the operator named keeps its mode; the seeds in it
	// are 0600 either way.
	if err := os.MkdirAll(dir, atrest.SecretDirMode); err != nil {
		return manifest{}, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// The set's bus key: offline, before any controlplane exists — which is
	// one of the reasons #448 pins a key instead of chaining to the mesh CA.
	busSigner, err := bustls.GenerateKey()
	if err != nil {
		return manifest{}, err
	}
	busKeyLine, err := bustls.EncodeKey(busSigner)
	if err != nil {
		return manifest{}, err
	}
	busPin, err := proto.BusPinForPublicKey(busSigner.Public())
	if err != nil {
		return manifest{}, err
	}

	var (
		preseed []busauth.PreseedToken
		man     = manifest{
			ClusterID:   clusterID,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			NATSURL:     natsURL,
			Enforce:     enforce,
			SSHKey:      sshKey != "",
			BusPin:      busPin,
			PreseedFile: "controlplane-bus-tokens.json",
		}
	)

	for _, n := range nodes {
		mn := manifestNode{ID: n.ID, Role: n.Role}
		if n.Role == "controlplane" {
			// The controlplane self-inits: no token in its seed (its api mints
			// its agent's token at start), dials its own NATS over loopback,
			// and is the recipient of the preseed (everyone else's hashes). A
			// matched set ships enforced — carried in the controlplane seed.
			mn.SeedFile = seedFileName(n)
			cpSeed := proto.Seed{
				Role:             proto.NodeRole(n.Role),
				NodeID:           n.ID,
				ClusterID:        clusterID,
				NATSURL:          loopbackNATSURL,
				BusPin:           busPin,
				SSHAuthorizedKey: sshKey,
				// The bus PRIVATE key, in the controlplane's seed only —
				// firstboot moves it off the card.
				BusKey: busKeyLine,
			}
			if enforce {
				cpSeed.BusAuth = "enforce"
			}
			seed, err := renderSeed(cpSeed)
			if err != nil {
				return manifest{}, fmt.Errorf("render the controlplane seed: %w", err)
			}
			if err := writeSecret(filepath.Join(dir, mn.SeedFile), seed); err != nil {
				return manifest{}, err
			}
			man.Nodes = append(man.Nodes, mn)
			continue
		}

		// Every other node gets a token bound to its id.
		plaintext, hash, err := busauth.GenerateToken()
		if err != nil {
			return manifest{}, fmt.Errorf("generate token for %s: %w", n.ID, err)
		}
		mn.SeedFile = seedFileName(n)
		mn.TokenHash = hash
		mn.Bound = true

		seed, err := renderSeed(proto.Seed{
			Role:             proto.NodeRole(n.Role),
			NodeID:           n.ID,
			ClusterID:        clusterID,
			NATSURL:          natsURL,
			JoinToken:        plaintext,
			BusPin:           busPin,
			SSHAuthorizedKey: sshKey,
		})
		if err != nil {
			return manifest{}, fmt.Errorf("render the seed for %s: %w", n.ID, err)
		}
		if err := writeSecret(filepath.Join(dir, mn.SeedFile), seed); err != nil {
			return manifest{}, err
		}
		// The role rides twice: as role, which the controlplane binds the
		// token to, and as the label, the display text it has always been.
		preseed = append(preseed, busauth.PreseedToken{Hash: hash, NodeID: n.ID, Label: n.Role, Role: proto.NodeRole(n.Role)})
		man.Nodes = append(man.Nodes, mn)
	}

	// Controlplane preseed (hashes + bindings only — no plaintext).
	preseedJSON, err := json.MarshalIndent(preseed, "", "  ")
	if err != nil {
		return manifest{}, fmt.Errorf("marshal preseed: %w", err)
	}
	if err := writePublic(filepath.Join(dir, man.PreseedFile), string(preseedJSON)+"\n"); err != nil {
		return manifest{}, err
	}

	manJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return manifest{}, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writePublic(filepath.Join(dir, "manifest.json"), string(manJSON)+"\n"); err != nil {
		return manifest{}, err
	}

	return man, nil
}

func seedFileName(n nodeSpec) string {
	if n.Role == "firewall" {
		return "seed-" + n.ID + ".seed.env" // OpenWrt /etc/rasputin/seed.env
	}
	return "seed-" + n.ID + ".env" // Buildroot FAT rasputin-seed.env
}

// renderSeed is the one renderer (proto.RenderSeed, methodology §5.6 and §7
// 4.2). buildrootSeed and openwrtSeed used to live here, byte-compatible with
// two more copies in the UI; there is now one, in proto, which the api's
// Add-node mint calls too. The role picks the file name and nothing else — the
// two images read the same keys.
//
// An error here fails provisioning rather than writing a seed a node cannot
// read: a bad seed on a FAT volume is discovered on a headless box.
func renderSeed(s proto.Seed) (string, error) {
	s.Origin = "rasputin-provision"
	return proto.RenderSeed(s)
}

// writeSecret writes a seed: it carries a join token or the bus private key,
// so it is 0600, including when a re-run replaces a file an earlier run (or
// an operator) left at a wider mode.
func writeSecret(path, content string) error {
	if err := atrest.WriteSecretFile(path, []byte(content)); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writePublic writes the preseed and the manifest, which are public by
// design: token hashes, node ids and roles, never a token.
func writePublic(path, content string) error {
	if err := atrest.WritePublicFile(path, []byte(content)); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
