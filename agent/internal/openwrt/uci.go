package openwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// CmdRunner runs a binary and returns its stdout. Injected so tests can
// drive the full apply/get cycle against a simulated UCI store without a
// real OpenWrt system. Mirrors the CmdRunner pattern in
// api/internal/mesh/supervisor_docker.go.
//
// Arguments are passed as argv directly to the process (no shell), so
// values containing spaces — e.g. UCI's space-joined multi-proto form
// "tcp udp" — need no quoting.
type CmdRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

// realRunner is the production CmdRunner: exec.CommandContext, stdout
// returned, stderr folded into the error so logs surface why uci/ubus
// rejected an invocation.
type realRunner struct{}

func (realRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w (stderr: %s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// UCIRealClient is the production UCIClient on real OpenWrt hardware
// (Node N). It renders the compiled state map to uci CLI invocations,
// commits, reloads, and reads observed reality back via `ubus call uci
// get` (JSON — far more robust to parse than `uci show` text).
//
// Ownership model (firewall-integration.md §13.4):
//
//   - /etc/config/firewall: Rasputin owns the MANAGED SECTION TYPES ONLY —
//     every `redirect` and `rule` section is deleted and recreated from the
//     state map on each apply. Operator-added sections of those types
//     (e.g. a LuCI-created redirect) are drift, and apply reverts them; this
//     is the locked reconcile model. `zone`, `defaults`, `forwarding`,
//     `include` and every other section type are never touched.
//   - /etc/config/network: SECTION-MERGED. Only the `wan` section, and only
//     `proto` + the proto-specific option keys present in the state map.
//     `ifname`/`device` (seeded by the OS image's uci-defaults) and all
//     other sections are never touched. An absent `network` key in the
//     state means "Rasputin doesn't manage WAN here" — the file is left
//     entirely alone, including any options a previous apply set.
//
// Ordering assumption (load-bearing for hash agreement): UCI preserves
// section creation order, Compile orders slice entries by (created_at, id),
// and apply recreates sections in slice order — so read-back order equals
// applied order and the canonical JSON (hence the hash) round-trips
// byte-identically.
//
// The manifest at <dir>/managed.json records whether the last apply
// included the `network` key and which network.wan option keys Rasputin
// set. Get uses the flag to decide whether to emit `network` at all (no
// manifest / never applied → omit, matching a Compile with zero wan_config
// rows); the key list tells the next apply which previously-set
// proto-specific options to delete (e.g. static→dhcp removes
// ipaddr/gateway/dns).
type UCIRealClient struct {
	mu           sync.Mutex
	runner       CmdRunner
	manifestPath string
}

// NewRealClient creates a UCIRealClient with the production exec runner.
// dir is the agent's openwrt state subdir (same dir the mock uses); it
// holds only managed.json. dir is created if missing.
func NewRealClient(dir string) (*UCIRealClient, error) {
	return newRealClient(dir, realRunner{})
}

func newRealClient(dir string, runner CmdRunner) (*UCIRealClient, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("openwrt-uci: mkdir %s: %w", dir, err)
	}
	return &UCIRealClient{
		runner:       runner,
		manifestPath: filepath.Join(dir, "managed.json"),
	}, nil
}

// managedManifest is the tiny local record of what Rasputin manages on
// this box beyond the always-managed firewall section types.
type managedManifest struct {
	// Network is true when the last successful apply included the
	// `network` key (Rasputin manages WAN).
	Network bool `json:"network"`
	// WANKeys are the network.wan option keys the last network-managing
	// apply set (including "proto"). Retained even across a subsequent
	// network-absent apply: those options are still on disk (absent means
	// "leave alone", not "clean up"), and the next network-managing apply
	// must know to delete the ones it no longer sets.
	WANKeys []string `json:"wanKeys,omitempty"`
}

// wanProtoKeys maps an observed network.wan proto to the proto-specific
// option keys Compile can emit for it. Get reads back `proto` + exactly
// these keys (intersected with what is actually set) so the observed state
// equals the applied state when nothing changed out-of-band, while an
// operator hand-editing proto or its options shows as drift.
// "_comment" is handled separately — Compile may emit it for any proto.
var wanProtoKeys = map[string][]string{
	"dhcp":   {"hostname"},
	"static": {"ipaddr", "gateway", "dns"},
	"pppoe":  {"username", "password", "service"},
	"none":   {},
}

// Apply renders state to uci commands, commits, reloads, and returns the
// hash of the state it applied. Since the input is applied verbatim,
// hashing the input (same canonicalization as the mock's hashState, which
// the api's firewall.Hash mirrors) is correct — the api compares this
// against its own compile hash and hard-errors on mismatch.
//
// No retries: the agent runs ON the firewall and a network reload may
// briefly bounce WAN (the agent itself talks over br-lan and survives);
// the api's saga layer owns retry semantics, and a blind re-apply here
// could double-apply mid-reload.
func (c *UCIRealClient) Apply(ctx context.Context, state map[string]any) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if state == nil {
		state = emptyState()
	}
	plan, err := planFromState(state)
	if err != nil {
		return "", fmt.Errorf("openwrt-uci: %w", err)
	}

	// --- /etc/config/firewall: full replace of managed section types ---
	// Revert first so staged-but-uncommitted changes from a crashed prior
	// apply can't leak into our commit.
	if _, err := c.runner.Run(ctx, "uci", "-q", "revert", "firewall"); err != nil {
		return "", fmt.Errorf("openwrt-uci: revert firewall: %w", err)
	}
	existing, err := c.readUbusConfig(ctx, "firewall")
	if err != nil {
		return "", fmt.Errorf("openwrt-uci: read firewall config: %w", err)
	}
	nRedirect, nRule := 0, 0
	for _, s := range existing {
		switch s.typ {
		case "redirect":
			nRedirect++
		case "rule":
			nRule++
		}
	}
	for _, cmd := range renderFirewallCommands(nRedirect, nRule, plan.redirects, plan.rules) {
		if _, err := c.runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			return "", fmt.Errorf("openwrt-uci: %w", err)
		}
	}

	// --- /etc/config/network: section-merge into network.wan ------------
	manifest, err := c.loadManifest()
	if err != nil {
		return "", err
	}
	networkTouched := false
	if plan.wan != nil {
		if _, err := c.runner.Run(ctx, "uci", "-q", "revert", "network"); err != nil {
			return "", fmt.Errorf("openwrt-uci: revert network: %w", err)
		}
		deletes, sets := renderNetworkCommands(manifest.WANKeys, plan.wan)
		for _, cmd := range deletes {
			// Idempotent cleanup: the option may already be gone (operator
			// deleted it by hand, or a previous apply was interrupted).
			// `uci -q delete` of a nonexistent option exits non-zero — that
			// must not fail the apply.
			_, _ = c.runner.Run(ctx, cmd[0], cmd[1:]...)
		}
		for _, cmd := range sets {
			if _, err := c.runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
				return "", fmt.Errorf("openwrt-uci: %w", err)
			}
		}
		if _, err := c.runner.Run(ctx, "uci", "commit", "network"); err != nil {
			return "", fmt.Errorf("openwrt-uci: commit network: %w", err)
		}
		manifest.Network = true
		manifest.WANKeys = sortedKeys(plan.wan)
		networkTouched = true
	} else {
		// Absent network key: leave /etc/config/network entirely alone.
		// WANKeys is deliberately retained — see managedManifest.
		manifest.Network = false
	}

	// Persist the manifest after the commits (it describes committed
	// state) and before the reloads (a failed reload doesn't change what
	// is on disk).
	if err := c.saveManifest(manifest); err != nil {
		return "", err
	}

	// --- reloads ---------------------------------------------------------
	if _, err := c.runner.Run(ctx, "/etc/init.d/firewall", "reload"); err != nil {
		return "", fmt.Errorf("openwrt-uci: firewall reload: %w", err)
	}
	if networkTouched {
		if _, err := c.runner.Run(ctx, "/etc/init.d/network", "reload"); err != nil {
			return "", fmt.Errorf("openwrt-uci: network reload: %w", err)
		}
	}

	return hashState(state)
}

// Get reads observed reality back via ubus and canonicalizes it into the
// exact map shape Compile produces, so an in-sync system hashes
// identically to the api's compiled intent state.
func (c *UCIRealClient) Get(ctx context.Context) (map[string]any, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sections, err := c.readUbusConfig(ctx, "firewall")
	if err != nil {
		return nil, "", fmt.Errorf("openwrt-uci: read firewall config: %w", err)
	}
	// Always-present (possibly empty) slices — matches Compile and the
	// mock's emptyState, so a fresh/empty box hashes to Compile(nil).
	redirects := []map[string]any{}
	rules := []map[string]any{}
	for _, s := range sections {
		entry := map[string]any{}
		for k, v := range s.opts {
			entry[k] = v
		}
		switch s.typ {
		case "redirect":
			redirects = append(redirects, entry)
		case "rule":
			rules = append(rules, entry)
		}
	}
	state := map[string]any{
		"firewall": map[string]any{
			"redirect": redirects,
			"rule":     rules,
		},
	}

	manifest, err := c.loadManifest()
	if err != nil {
		return nil, "", err
	}
	if manifest.Network {
		observed, err := c.readUbusSection(ctx, "network", "wan")
		if err != nil {
			return nil, "", fmt.Errorf("openwrt-uci: read network.wan: %w", err)
		}
		wan := map[string]any{}
		if observed != nil {
			if p, ok := observed["proto"]; ok {
				wan["proto"] = p
				for _, k := range wanProtoKeys[p] {
					if v, ok := observed[k]; ok {
						wan[k] = v
					}
				}
			}
			if v, ok := observed["_comment"]; ok {
				wan["_comment"] = v
			}
		}
		// observed == nil (section deleted out-of-band) leaves wan empty —
		// that never matches a compiled state, so it surfaces as drift.
		state["network"] = map[string]any{"wan": wan}
	}

	h, err := hashState(state)
	return state, h, err
}

// ----- ubus read-back -------------------------------------------------------

// uciSection is one section of a UCI config in creation order.
type uciSection struct {
	typ  string
	opts map[string]string
}

// readUbusConfig fetches a whole config via `ubus call uci get` and returns
// its sections ordered by UCI's ".index" (creation order). A missing config
// returns (nil, nil) — callers treat that as empty.
func (c *UCIRealClient) readUbusConfig(ctx context.Context, config string) ([]uciSection, error) {
	out, err := c.runner.Run(ctx, "ubus", "call", "uci", "get", fmt.Sprintf(`{"config":%q}`, config))
	if err != nil {
		if isUbusNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var parsed struct {
		Values map[string]map[string]any `json:"values"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, fmt.Errorf("parse ubus uci get %s: %w", config, err)
	}
	type indexed struct {
		idx float64
		sec uciSection
	}
	all := make([]indexed, 0, len(parsed.Values))
	for name, raw := range parsed.Values {
		sec := uciSection{opts: map[string]string{}}
		idx := float64(0)
		for k, v := range raw {
			switch k {
			case ".type":
				if s, ok := v.(string); ok {
					sec.typ = s
				}
				continue
			case ".index":
				if f, ok := v.(float64); ok {
					idx = f
				}
				continue
			}
			if strings.HasPrefix(k, ".") {
				continue // .anonymous, .name — UCI bookkeeping
			}
			s, err := optionString(v)
			if err != nil {
				return nil, fmt.Errorf("section %s option %s: %w", name, k, err)
			}
			sec.opts[k] = s
		}
		all = append(all, indexed{idx: idx, sec: sec})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].idx < all[j].idx })
	sections := make([]uciSection, len(all))
	for i, e := range all {
		sections[i] = e.sec
	}
	return sections, nil
}

// readUbusSection fetches a single section's options. A missing config or
// section returns (nil, nil).
func (c *UCIRealClient) readUbusSection(ctx context.Context, config, section string) (map[string]string, error) {
	out, err := c.runner.Run(ctx, "ubus", "call", "uci", "get",
		fmt.Sprintf(`{"config":%q,"section":%q}`, config, section))
	if err != nil {
		if isUbusNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var parsed struct {
		Values map[string]any `json:"values"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, fmt.Errorf("parse ubus uci get %s.%s: %w", config, section, err)
	}
	opts := map[string]string{}
	for k, v := range parsed.Values {
		if strings.HasPrefix(k, ".") {
			continue
		}
		s, err := optionString(v)
		if err != nil {
			return nil, fmt.Errorf("section %s.%s option %s: %w", config, section, k, err)
		}
		opts[k] = s
	}
	return opts, nil
}

// optionString canonicalizes a ubus option value. Options come back as
// strings; UCI `list` entries come back as JSON arrays — those are
// re-joined with spaces to match Compile's space-joined emission (e.g.
// proto "tcp udp", dns "1.1.1.1 8.8.8.8"). Values stay verbatim strings:
// boolean-ish "1"/"0" are NOT normalized, matching Compile's log:"1".
func optionString(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return "", fmt.Errorf("unexpected list element type %T", e)
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " "), nil
	default:
		return "", fmt.Errorf("unexpected option value type %T", v)
	}
}

// isUbusNotFound matches the ubus CLI's missing-config/section failure
// ("Command failed: Not found", exit status 4). Treated as empty state so
// a box with no /etc/config/firewall behaves like the mock's fresh
// install.
func isUbusNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")
}

// ----- manifest --------------------------------------------------------------

// loadManifest reads managed.json; a missing file is the zero manifest
// (never applied → Rasputin doesn't manage WAN).
func (c *UCIRealClient) loadManifest() (managedManifest, error) {
	var m managedManifest
	b, err := os.ReadFile(c.manifestPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return m, nil
		}
		return m, fmt.Errorf("openwrt-uci: read %s: %w", c.manifestPath, err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("openwrt-uci: parse %s: %w", c.manifestPath, err)
	}
	return m, nil
}

// saveManifest writes managed.json atomically (tmp + rename), mirroring
// the mock's state writes.
func (c *UCIRealClient) saveManifest(m managedManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("openwrt-uci: marshal manifest: %w", err)
	}
	tmp := c.manifestPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("openwrt-uci: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, c.manifestPath); err != nil {
		return fmt.Errorf("openwrt-uci: rename manifest: %w", err)
	}
	return nil
}
