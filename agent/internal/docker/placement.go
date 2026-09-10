package docker

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// design/storage.md §6.4's per-app placement, applied at the only moment and on
// the only machine where it can be applied safely: the deploy, on the node,
// after §6.3's marker has proved the disk is mounted.
//
// # Why the agent and not the api
//
// The api knows which disk an operator chose (a partition UUID) and nothing
// else. It does not know where that disk is mounted — under §6.5 the agent
// mounts it, at its own startup, into a root the api never sees — and it cannot
// know whether the mount survived the last reboot. Both facts are local and
// perishable, so the resolution is local and happens per deploy.
//
// # Why named volumes and not the Docker state root
//
// §6.4 rejects repointing /var/lib/rasputin/docker: it would put every app AND
// the controlplane's own Docker workloads on a removable disk, so pulling that
// disk would break the cluster instead of one app. Rewriting one project's
// named volumes keeps the blast radius to the app that opted in, which is the
// whole point of making placement per-app.

// DataDiskResolver answers "where is the claimed data disk partUUID mounted on
// this node, and is the filesystem there really that disk?".
//
// It is a function value rather than a direct call into the storage package so
// that this package's tests can point a placement at a directory they control —
// the real answer lives under /var/lib/rasputin/data, which no test can write
// to. The production value is storage.ResolveDataDisk and there is no other.
//
// A nil resolver means this agent cannot place anything, and every placed
// deploy is refused rather than quietly demoted to the boot medium.
type DataDiskResolver func(partUUID string) (mountPath string, err error)

// safePathSegment is the alphabet the two operator-supplied strings that become
// directory names may use: the app id and each compose volume key.
//
// Both are checked, with the same rule, because both end up as a segment of a
// path under the operator's data disk — and neither arrives from somewhere this
// agent is entitled to trust. A compose file is operator input like any other,
// and the api validating the app id is the api's business, not a fact this side
// of the wire can assume. `.` and `..` are refused by the leading character
// class, and `a/b` by the alphabet, so neither needs a rule of its own.
var safePathSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// placeOnDataDisk rewrites composeYAML so every named volume of app appID is a
// bind onto the claimed data disk partUUID, and returns the rewritten document.
//
// It REFUSES rather than degrades, on every path. There is no outcome where
// this returns a compose that leaves a placed app's volumes on the boot medium:
// an operator who chose a data disk and got the boot medium anyway has the
// §6.3 failure with a success message on top of it.
//
// Directories are created only after the marker verifies, and only under the
// verified mount. The compose `local` driver's bind form does not create the
// device path — docker fails the volume if it is missing — so creating them is
// part of placing, not a convenience.
func placeOnDataDisk(appID, composeYAML, partUUID string, resolve DataDiskResolver) (string, error) {
	if resolve == nil {
		return "", fmt.Errorf("this agent cannot place apps on a data disk: no data-disk resolver is wired, so the app's volumes would land on the boot medium — refusing rather than deploying it in the wrong place")
	}
	if !safePathSegment.MatchString(appID) {
		return "", fmt.Errorf("app id %q is not a usable directory name, and a placed app's volumes live under <data disk>/apps/<app id>", appID)
	}
	// §6.3, and the whole of the enforcement: the marker on the mounted
	// filesystem, never "the mount point is non-empty". An unmounted mount
	// point a previous deploy already filled is precisely the case being
	// caught, and it is not empty.
	mount, err := resolve(partUUID)
	if err != nil {
		return "", fmt.Errorf("refusing to deploy onto data disk %s: %w", partUUID, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(composeYAML), &doc); err != nil {
		return "", fmt.Errorf("this app's compose could not be parsed, so its volumes cannot be placed on data disk %s: %w", partUUID, err)
	}
	root, err := documentMapping(&doc)
	if err != nil {
		return "", fmt.Errorf("this app's compose is not a compose file, so its volumes cannot be placed on data disk %s: %w", partUUID, err)
	}
	volumes, ok := mappingValue(root, "volumes")
	if !ok || volumes.Kind != yaml.MappingNode || len(volumes.Content) == 0 {
		// Refused, not skipped. The operator asked for this app's data to be
		// on their disk; an app with no named volumes has no data to put
		// there, and reporting success would tell them the opposite of what
		// happened. It is also the likeliest way a placement lands on the
		// wrong app.
		return "", fmt.Errorf("this app declares no named volumes, so there is nothing to place on data disk %s — the placement would have no effect and is refused rather than reported as done", partUUID)
	}

	appRoot := filepath.Join(mount, "apps", appID)
	for i := 0; i+1 < len(volumes.Content); i += 2 {
		key, val := volumes.Content[i], volumes.Content[i+1]
		name := key.Value
		if key.Kind != yaml.ScalarNode || !safePathSegment.MatchString(name) {
			return "", fmt.Errorf("volume %q cannot be placed on data disk %s: a volume name has to be a plain directory name", name, partUUID)
		}
		if err := checkPlaceableVolume(name, val, partUUID); err != nil {
			return "", err
		}
		device := filepath.Join(appRoot, name)
		if err := os.MkdirAll(device, 0o755); err != nil {
			return "", fmt.Errorf("volume %q could not be created on data disk %s at %s: %w", name, partUUID, device, err)
		}
		volumes.Content[i+1] = bindVolumeNode(val, device)
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	// Two spaces, because that is what every compose file in the catalog uses
	// and this document is written to disk where an operator debugging a node
	// will read it beside them.
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", fmt.Errorf("the placed compose for data disk %s could not be written: %w", partUUID, err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("the placed compose for data disk %s could not be written: %w", partUUID, err)
	}
	return out.String(), nil
}

// checkPlaceableVolume refuses a volume this agent must not rewrite.
//
// Each case is a volume whose storage somebody else already decided. Silently
// overriding one would move data the operator put somewhere deliberately;
// silently SKIPPING one would leave it on the boot medium under a deploy that
// reported success. Both are worse than saying which volume and why, so a
// mixed compose is refused whole rather than placed in part.
func checkPlaceableVolume(name string, val *yaml.Node, partUUID string) error {
	if val == nil || val.Kind != yaml.MappingNode {
		// The ordinary shape: `data:` with nothing under it, or `data: {}`.
		// Compose creates the volume itself, which is exactly what placement
		// takes over.
		return nil
	}
	if ext, ok := mappingValue(val, "external"); ok && ext.Value != "false" {
		return fmt.Errorf("volume %q is declared external, so compose does not create it and this node must not place it on data disk %s — remove the placement or the external declaration", name, partUUID)
	}
	if drv, ok := mappingValue(val, "driver"); ok && strings.TrimSpace(drv.Value) != "local" {
		return fmt.Errorf("volume %q uses the %q volume driver, and placing it on data disk %s would replace that driver with a bind mount — refusing to change where an app was deliberately told to store its data", name, drv.Value, partUUID)
	}
	if _, ok := mappingValue(val, "driver_opts"); ok {
		return fmt.Errorf("volume %q already carries driver_opts, so something has already decided where it is stored — refusing to overwrite that with a bind onto data disk %s", name, partUUID)
	}
	return nil
}

// bindVolumeNode returns the volume declaration that binds device, preserving
// whatever else the original carried (labels, for instance) so placement adds
// storage without editing the rest of the operator's file.
func bindVolumeNode(val *yaml.Node, device string) *yaml.Node {
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if val != nil && val.Kind == yaml.MappingNode {
		out.Content = append(out.Content, val.Content...)
		out.HeadComment, out.LineComment, out.FootComment = val.HeadComment, val.LineComment, val.FootComment
	}
	setMappingValue(out, "driver", scalarNode("local"))
	// The compose `local` driver's bind form: an existing directory presented
	// to the container as if it were a volume. `type: none` + `o: bind` is
	// mount(8)'s bind, spelled the way compose passes it through.
	opts := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setMappingValue(opts, "type", scalarNode("none"))
	setMappingValue(opts, "o", scalarNode("bind"))
	setMappingValue(opts, "device", scalarNode(device))
	setMappingValue(out, "driver_opts", opts)
	return out
}

// documentMapping unwraps the document node an empty-or-scalar compose would
// not have, and returns the top-level mapping.
func documentMapping(doc *yaml.Node) (*yaml.Node, error) {
	n := doc
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil, fmt.Errorf("it is empty")
		}
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("its top level is not a mapping")
	}
	return n, nil
}

// mappingValue looks a key up in a YAML mapping node, whose Content is a flat
// key, value, key, value list.
func mappingValue(m *yaml.Node, key string) (*yaml.Node, bool) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], true
		}
	}
	return nil, false
}

// setMappingValue replaces key's value in place when it is present and appends
// it otherwise, so an existing declaration keeps its position in the file.
func setMappingValue(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, scalarNode(key), val)
}

func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}
