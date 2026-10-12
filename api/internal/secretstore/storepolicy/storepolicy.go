// Package storepolicy is the one source of the node secrets store's fixed
// policy text (geekdojo/geekdojo-brain#804; ADR-0010 S9).
//
// Each policy is a file in this directory, <name>.hcl, embedded here and
// packed by scripts/pack-store-policy.sh into the api release tarball as
// openbao-policy/<name>.hcl. rasputin-os installs those files on the image,
// and the store's self-init loads them through a `file` source, so the text
// the store enforces is the text these tests check. rasputin-os's drift check
// compares the tarball's copy with this directory at the release tag.
//
// No shipped binary imports this package: only tests do.
package storepolicy

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

const (
	// Mount is the kv-v2 mount the policies grant paths under.
	Mount = "rasputin-secrets"
	// APIPolicy is the api's policy, bound to the api's cert role.
	APIPolicy = "rasputin-api"
	// SealRotatePolicy is the seal rotation job's policy (#830), bound to its
	// own cert role.
	SealRotatePolicy = "rasputin-seal-rotate"
	// ProvisionerPolicy is the store provisioner's policy (#805), bound to its
	// own cert role: it adds mounts and roles under Namespace and binds them
	// only to BindablePolicy.
	ProvisionerPolicy = "rasputin-provisioner"
	// BindablePolicy is the one policy a provisioned role may bind (#805,
	// D-805-A): a lookup of the token's own self.
	BindablePolicy = "rasputin-bindable"
	// Namespace is the prefix of every mount and role the provisioner may add.
	// No fixed mount, role or policy name starts with it.
	Namespace = "rasputin-rel-"
)

const ext = ".hcl"

//go:embed *.hcl
var files embed.FS

// Names returns every policy's name, sorted: each embedded <name>.hcl.
func Names() []string {
	ents, err := fs.ReadDir(files, ".")
	if err != nil {
		// The embedded tree is fixed at build time and "." always exists in
		// it, so this cannot fail at run time; a panic says the build broke.
		panic(fmt.Sprintf("storepolicy: read the embedded policies: %v", err))
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, strings.TrimSuffix(e.Name(), ext))
	}
	sort.Strings(names)
	return names
}

// Text returns the named policy's text, byte for byte as it ships.
func Text(name string) ([]byte, error) {
	// embed.FS refuses any name that is not a plain file in this directory
	// (a path with .. or a separator included), so every miss is the same
	// answer.
	b, err := files.ReadFile(name + ext)
	if err != nil {
		return nil, fmt.Errorf("storepolicy: no policy named %q", name)
	}
	return b, nil
}
