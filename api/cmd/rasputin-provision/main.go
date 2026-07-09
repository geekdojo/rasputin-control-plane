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
//	  [--nats-url nats://rasputin.local:4222] [--out ./out/home1] \
//	  [--ssh-authorized-key-file ~/.ssh/id_ed25519.pub]
//
// A --node value is "role[:node-id]". When the id is omitted it's auto-assigned
// as "<cluster-id>-<role><seq>". Roles: controlplane | firewall | compute | storage.
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

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
)

const defaultNATSURL = "nats://rasputin.local:4222"

// loopbackNATSURL is what the controlplane's own co-located agent dials so it's
// trusted via loopback (it carries no token). See token-provisioning-pipeline.md.
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
		natsURL    = flag.String("nats-url", defaultNATSURL, "control-plane NATS URL baked into non-controlplane seeds")
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

	dir := *outDir
	if dir == "" {
		dir = filepath.Join("out", *clusterID)
	}
	man, err := generate(*clusterID, *natsURL, dir, nodes, *enforce, key)
	if err != nil {
		return err
	}

	fmt.Printf("provisioned %d nodes for cluster %q → %s\n", len(man.Nodes), *clusterID, dir)
	fmt.Printf("  • per-node seeds (the tokens live ONLY here — treat as secrets)\n")
	fmt.Printf("  • %s → the controlplane's seed (preload via firstboot)\n", man.PreseedFile)
	fmt.Printf("  • manifest.json → audit record (no plaintext)\n")
	if man.SSHKey {
		fmt.Printf("  • every seed carries the operator SSH key (key-only network SSH enabled)\n")
	} else {
		fmt.Printf("  • NO SSH key in the seeds — images bake none, so the cluster is console/UI-only; pass --ssh-authorized-key[-file] for network SSH\n")
	}
	return nil
}

// resolveSSHKey merges the two --ssh-authorized-key* flags into one validated
// key line ("" = no key, a valid choice: console/UI-only cluster).
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
	// The seed renders it double-quoted (the seed file is sourced by sh), so a
	// quote in the value would break every node's provisioning.
	if strings.ContainsAny(literal, `"$\`+"`") {
		return "", fmt.Errorf(`ssh authorized key must not contain ", $, \ or backtick (the seed is sourced by sh)`)
	}
	f := strings.Fields(literal)
	if len(f) < 2 || !(strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-") || strings.HasPrefix(f[0], "sk-")) {
		return "", fmt.Errorf("value doesn't look like an OpenSSH public key (want e.g. \"ssh-ed25519 AAAA... comment\")")
	}
	return literal, nil
}

// generate assigns ids, validates the set, and writes all artifacts into dir.
// Returns the manifest. Pure enough to unit-test end-to-end. sshKey ("" = none)
// is the operator's public key, already validated by resolveSSHKey.
func generate(clusterID, natsURL, dir string, nodes nodeList, enforce bool, sshKey string) (manifest, error) {
	if clusterID == "" {
		return manifest{}, fmt.Errorf("cluster id is required")
	}
	if len(nodes) == 0 {
		return manifest{}, fmt.Errorf("at least one node is required")
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
		if seen[nodes[i].ID] {
			return manifest{}, fmt.Errorf("duplicate node id %q", nodes[i].ID)
		}
		seen[nodes[i].ID] = true
	}
	if cpCount != 1 {
		return manifest{}, fmt.Errorf("a matched set needs exactly one controlplane node, got %d", cpCount)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return manifest{}, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	var (
		preseed []busauth.PreseedToken
		man     = manifest{
			ClusterID:   clusterID,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			NATSURL:     natsURL,
			Enforce:     enforce,
			SSHKey:      sshKey != "",
			PreseedFile: "controlplane-bus-tokens.json",
		}
	)

	for _, n := range nodes {
		mn := manifestNode{ID: n.ID, Role: n.Role}
		if n.Role == "controlplane" {
			// The controlplane self-inits: no token, dials its own loopback NATS,
			// and is the recipient of the preseed (everyone else's hashes). A
			// matched set ships enforced — carried in the controlplane seed.
			mn.SeedFile = seedFileName(n)
			seed := buildrootSeed(n.Role, n.ID, loopbackNATSURL, "", sshKey)
			if enforce {
				seed += "RASPUTIN_BUS_AUTH=enforce\n"
			}
			if err := writeFile(filepath.Join(dir, mn.SeedFile), seed, 0o600); err != nil {
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

		var seed string
		if n.Role == "firewall" {
			seed = openwrtSeed(n.ID, natsURL, plaintext, sshKey)
		} else {
			seed = buildrootSeed(n.Role, n.ID, natsURL, plaintext, sshKey)
		}
		if err := writeFile(filepath.Join(dir, mn.SeedFile), seed, 0o600); err != nil {
			return manifest{}, err
		}
		preseed = append(preseed, busauth.PreseedToken{Hash: hash, NodeID: n.ID, Label: n.Role})
		man.Nodes = append(man.Nodes, mn)
	}

	// Controlplane preseed (hashes + bindings only — no plaintext).
	preseedJSON, err := json.MarshalIndent(preseed, "", "  ")
	if err != nil {
		return manifest{}, fmt.Errorf("marshal preseed: %w", err)
	}
	if err := writeFile(filepath.Join(dir, man.PreseedFile), string(preseedJSON)+"\n", 0o644); err != nil {
		return manifest{}, err
	}

	manJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return manifest{}, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeFile(filepath.Join(dir, "manifest.json"), string(manJSON)+"\n", 0o644); err != nil {
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

// buildrootSeed renders the FAT rasputin-seed.env consumed by the Buildroot
// firstboot oneshot (provisioning.md §1). An empty token (controlplane) omits
// the join-token line; an empty sshKey omits the key line (console/UI-only).
// The key line is double-quoted — the seed is sourced by sh and the value
// contains spaces; an unquoted key would break every field's sourcing.
func buildrootSeed(role, id, natsURL, token, sshKey string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# rasputin-seed.env — generated by rasputin-provision\n")
	fmt.Fprintf(&b, "RASPUTIN_NODE_ROLE=%s\n", role)
	fmt.Fprintf(&b, "RASPUTIN_NODE_ID=%s\n", id)
	fmt.Fprintf(&b, "RASPUTIN_NATS_URL=%s\n", natsURL)
	if token != "" {
		fmt.Fprintf(&b, "RASPUTIN_CP_JOIN_TOKEN=%s\n", token)
	}
	if sshKey != "" {
		fmt.Fprintf(&b, "RASPUTIN_SSH_AUTHORIZED_KEY=%q\n", sshKey)
	}
	return b.String()
}

// openwrtSeed renders the firewall image's /etc/rasputin/seed.env. RASPUTIN_NODE_ID
// is honored by apply-seed (overriding the on-box DMI/machine-id derivation) so
// the bound token matches. sshKey as in buildrootSeed.
func openwrtSeed(id, natsURL, token, sshKey string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# seed.env (firewall) — generated by rasputin-provision\n")
	fmt.Fprintf(&b, "RASPUTIN_NODE_ROLE=firewall\n")
	fmt.Fprintf(&b, "RASPUTIN_NODE_ID=%s\n", id)
	fmt.Fprintf(&b, "RASPUTIN_NATS_URL=%s\n", natsURL)
	fmt.Fprintf(&b, "RASPUTIN_CP_JOIN_TOKEN=%s\n", token)
	if sshKey != "" {
		fmt.Fprintf(&b, "RASPUTIN_SSH_AUTHORIZED_KEY=%q\n", sshKey)
	}
	return b.String()
}

func writeFile(path, content string, mode os.FileMode) error {
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
