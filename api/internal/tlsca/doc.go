// Package tlsca is the controlplane's generic TLS certificate authority: one
// code path that ensures a CA on disk and mints leaves under it, run once per
// instance. An instance is a Config value and nothing else, so two CAs cannot
// drift apart in how they are created, loaded, refused or renewed.
//
// There are two instances, both kept in the trust dir:
//
//   - The controlplane CA (ControlplaneConfig, "TLS-A" in
//     design/control-plane/certificates.md) signs every HTTPS leaf the
//     controlplane runs: the api, Headscale and the per-app leaves. Operator
//     devices install it once and every node is shipped it, so every
//     controlplane HTTPS service is "real TLS" to them.
//   - The store CA (StoreConfig) is trusted by the secret store's listener and
//     by nothing else. It never enters a node, browser or collector bundle, and
//     the two CAs never chain to each other, so a listener that trusts the
//     store CA alone refuses every controlplane-CA leaf.
//
// Both are separate from the bundle-signing CA: that root belongs to
// Rasputin-Inc and never leaves Geekdojo's offline custody. Mixing it with a
// TLS CA would either leak the cross-fleet intermediate onto every customer's
// box, or make operators trust Rasputin-Inc keys to verify their own Rasputin.
//
// Every leaf carries exactly one explicit ExtKeyUsage (Usage), checked against
// the instance's Config.Usages.
//
// # Compatibility names
//
// These names predate the package and say "mesh" because the controlplane CA
// began as the mesh's. They are on disk, on the wire, in backups or in the OS
// images, and are kept rather than migrated:
//
//   - trust/mesh-ca.pem and trust/mesh-ca.key, and the backup archive members
//     trust/mesh-ca.*
//   - the node bundle /var/lib/rasputin/mesh/tailscaled-ca.pem and its override
//     RASPUTIN_MESH_CA_BUNDLE
//   - the OS drop-in 10-rasputin-mesh-ca.conf
//   - the download routes /mesh-ca.pem and /mesh-ca.crt, and the collector's
//     /etc/alloy/certs/mesh-ca.pem
//   - the registration key meshCaFingerprint, the enroll field meshCaPem, and
//     the job kind mesh.leaf_sweep
//   - the controlplane CA's subject, "Rasputin Mesh CA (<install>)", which
//     installed devices already show
package tlsca
