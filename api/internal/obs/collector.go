package obs

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"text/template"
)

// Per-node observability collector (Slice 1.2b, observability-stack.md §3.10).
//
// A collector is a single Grafana Alloy container the controlplane deploys to
// each Docker-capable node via the existing `docker.deploy` command. It runs
// cAdvisor and remote-writes the per-container metrics to the api's mTLS
// ingress (obs_ingest.go), which stamps the node_id server-side. That's what
// makes a container on `c02` show up in c02's Containers drawer, while VM stays
// loopback-only on the controlplane.
//
// Two shapes, while both kinds of node are in the fleet
// (geekdojo/geekdojo-brain#515):
//
//   - NODE KEY (the target). The collector presents the key the node
//     generated, in a certificate the node self-signed, and it trusts the
//     control plane by the bus certificate's exact bytes. The key never leaves
//     the node and is never in the compose file: the container bind-mounts it
//     read-only from the node's key directory. The api puts only public bytes
//     in the compose — the certificate's path and the bus certificate itself.
//   - MESH LEAF (legacy). The control plane mints the node a client leaf under
//     the mesh CA and puts the leaf, its KEY and the CA into the compose as
//     inline `configs` content. That is the shape this file has always had,
//     and it is why the key sat in a 0644 file on the node. It is used only
//     for a node whose agent has not registered a collector key.
//
// Either way the whole deployment is one compose string, because
// `AppDeployCmd` carries only that and the agent writes no other files.

const (
	// collectorContainerName is the collector's container name on the node.
	// One collector per node, so a fixed name is fine; the compose project
	// (rasp_<appID>) namespaces it against any other stacks on the box.
	collectorContainerName = "rasputin-obs-collector"

	// collectorConfigDir is where the inline configs land inside the container.
	collectorConfigPath   = "/etc/alloy/config.alloy"
	collectorLeafCertPath = "/etc/alloy/certs/leaf.pem"
	// Where the node's own collector certificate and key are mounted, in the
	// node-key shape.
	collectorNodeKeyCertPath = "/etc/alloy/certs/node.crt"
	collectorNodeKeyPath     = "/etc/alloy/certs/node.key"
	collectorLeafKeyPath     = "/etc/alloy/certs/leaf.key"
	collectorMeshCAPath      = "/etc/alloy/certs/mesh-ca.pem"

	// collectorDataRoot is the appliance's FIXED Docker data-root — the OS
	// image pins it here (§3.9b). Unlike the controlplane supervisor, which
	// discovers the data-root via `docker info`, a remote collector can't run
	// that during compose rendering, so it relies on the fixed convention.
	collectorDataRoot = "/var/lib/rasputin/docker"
)

// CollectorSpec is the input to BuildCollectorCompose. The three PEM blobs are
// supplied by the caller (the reconcile saga, Piece 4), which mints the
// client leaf under the mesh CA — the obs package stays decoupled from mesh.
type CollectorSpec struct {
	// NodeID labels the metrics (external_labels{node_id}) and is the CN of
	// the client leaf. The ingress ultimately re-derives node_id from the
	// verified cert and overrides this via VM's extra_label, so it's belt +
	// suspenders here — but it keeps the collector's own view self-consistent.
	NodeID string

	// IngressBaseURL is the api's mTLS ingress base, e.g.
	// https://rasputin.local:8443 — the builder appends the metrics
	// (/api/obs/ingest) and logs (/api/obs/logs/ingest) paths. ServerName is the
	// TLS SNI / verified name (the api server-leaf SAN, e.g. rasputin.local).
	// Both come from DeriveIngressEndpoint so they track the canonical
	// hostname, never a hardcoded literal (two-cluster forward-compat).
	IngressBaseURL string
	ServerName     string

	// The mTLS material, PEM-encoded, for the LEGACY shape only.
	// LeafCertPEM/LeafKeyPEM are the node's client leaf (minted with
	// LeafSpec.ClientAuth); MeshCAPEM is the CA the collector trusts for the
	// api's server cert. Leave all three empty for the node-key shape.
	LeafCertPEM string
	LeafKeyPEM  string
	MeshCAPEM   string

	// NodeKeyCertPath / NodeKeyPath are the node's own collector certificate
	// and key, as absolute paths ON THE NODE (proto.NodeCertPath /
	// proto.NodeKeyPath). Set both for the node-key shape. The compose
	// bind-mounts them read-only; nothing about the key is in the compose.
	NodeKeyCertPath string
	NodeKeyPath     string

	// BusCertPEM is the control plane's bus certificate, which the collector
	// trusts as its only CA in the node-key shape — by exact bytes, not by a
	// chain, which is the same thing the node's bus pin does one layer down.
	BusCertPEM string

	// AlloyImage overrides the pinned collector image. Defaults to the same
	// tag the controlplane obs stack uses so the fleet runs one Alloy version.
	AlloyImage string
}

// collectorAlloyTmpl is the collector's Alloy config in River syntax: cAdvisor
// (docker_only) scraped into a remote_write, AND every container's logs tailed
// into a loki.write — both presenting the node's client leaf over mTLS to the
// api ingress (§3.10 metrics, §3.11 logs). No self-metrics / Grafana.
var collectorAlloyTmpl = template.Must(template.New("collector-alloy").Parse(
	`// Generated by rasputin-api obs collector builder — do not hand-edit.
// Per-node cAdvisor + container logs -> mTLS ingress on the control plane.

prometheus.exporter.cadvisor "containers" {
  docker_only = true
}

prometheus.scrape "cadvisor" {
  targets         = prometheus.exporter.cadvisor.containers.targets
  forward_to      = [prometheus.remote_write.ingress.receiver]
  scrape_interval = "15s"
}

prometheus.remote_write "ingress" {
  external_labels = {
    node_id = "{{.NodeID}}",
  }
  endpoint {
    url = "{{.MetricsIngressURL}}"
    tls_config {
      cert_file   = "{{.ClientCertPath}}"
      key_file    = "{{.ClientKeyPath}}"
{{.TrustBlock}}
      server_name = "{{.ServerName}}"
    }
  }
}

// Container logs -> Loki push through the mTLS ingress. node_id rides in
// external_labels so the collector's own view is self-consistent, but it is
// not what decides attribution: the ingress overwrites node_id on every stream
// with the node id on the verified client leaf (Loki has no extra_label
// equivalent, so the api rewrites the label instead).
loki.write "ingress" {
  external_labels = {
    node_id = "{{.NodeID}}",
  }
  endpoint {
    url = "{{.LogsIngressURL}}"
    tls_config {
      cert_file   = "{{.ClientCertPath}}"
      key_file    = "{{.ClientKeyPath}}"
{{.TrustBlock}}
      server_name = "{{.ServerName}}"
    }
  }
}

discovery.docker "containers" {
  host             = "unix:///var/run/docker.sock"
  refresh_interval = "30s"
}

discovery.relabel "containers" {
  targets = discovery.docker.containers.targets
  rule {
    source_labels = ["__meta_docker_container_name"]
    regex         = "/(.*)"
    target_label  = "container"
  }
  rule {
    source_labels = ["__meta_docker_container_log_stream"]
    target_label  = "stream"
  }
  rule {
    source_labels = ["__meta_docker_container_label_com_docker_compose_service"]
    target_label  = "compose_service"
  }
}

loki.source.docker "containers" {
  host       = "unix:///var/run/docker.sock"
  targets    = discovery.relabel.containers.output
  forward_to = [loki.write.ingress.receiver]
}
`))

// collectorComposeTmpl renders the collector's compose file. The Alloy config
// rides as inline `configs` content (Compose >= v2.23.1), and so do the legacy
// mesh leaf's PEM files. In the node-key shape the client material is not in
// the file at all: it is bind-mounted read-only from the node's own key
// directory, so the collector's private key stays a 0600 file on the node
// instead of sitting inside a compose file the agent writes.
// network_mode: host is load-bearing — a bridge-network container
// can't resolve the controlplane's mDNS `rasputin.local` name (Docker's DNS
// forwarder bypasses the host's nss-mdns), whereas host networking uses the
// node's own resolver, exactly as the agent already does for NATS. Host
// networking also gives cAdvisor its usual view; the config/cert bind-in via
// `configs` is unaffected by it.
var collectorComposeTmpl = template.Must(template.New("collector-compose").
	Funcs(template.FuncMap{"indent": indentBlock}).
	Parse(`# Generated by rasputin-api obs collector builder — do not hand-edit.
# Per-node observability collector (Slice 1.2b). See observability-stack.md §3.10.
services:
  alloy:
    image: {{.AlloyImage}}
    container_name: ` + collectorContainerName + `
    restart: unless-stopped
    # Host networking so the collector can resolve rasputin.local (mDNS) to
    # reach the control-plane mTLS ingress — a bridge container cannot.
    network_mode: host
    command:
      - run
      # Loopback only, and NOT a privilege boundary: network_mode: host
      # puts this on the NODE's loopback, where any local user and any
      # host-network container can reach it. Alloy v1.4.2 has no
      # authentication for this server, no unix-socket option and no way
      # to turn it off, and host networking is load-bearing here (mDNS),
      # so the exposure stands — tracked in geekdojo-brain#452.
      - --server.http.listen-addr=127.0.0.1:12345
      # What CAN go: the pprof endpoints, which nothing uses and which
      # hang off that same unauthenticated server.
      - --server.http.enable-pprof=false
      - ` + collectorConfigPath + `
    configs:
      - source: alloy_config
        target: ` + collectorConfigPath + `
{{- if .Legacy }}
      - source: leaf_cert
        target: ` + collectorLeafCertPath + `
      - source: leaf_key
        target: ` + collectorLeafKeyPath + `
      - source: mesh_ca
        target: ` + collectorMeshCAPath + `
{{- end }}
    volumes:
      # cAdvisor needs the Docker socket, the host cgroup tree, and Docker's
      # data-root (the fixed appliance path, §3.9b) to enumerate containers.
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /sys:/sys:ro
      - ` + collectorDataRoot + `:` + collectorDataRoot + `:ro
{{- if not .Legacy }}
      # The node's own collector key and its self-signed certificate,
      # read-only. The key is 0600 on the node and is never copied into this
      # file; the container runs as uid 0, which is what makes a 0600
      # read-only mount readable to it.
      - {{.NodeKeyCertPath}}:{{.ClientCertPath}}:ro
      - {{.NodeKeyPath}}:{{.ClientKeyPath}}:ro
{{- end }}

configs:
  alloy_config:
    content: |
{{ indent 6 .AlloyConfig }}
{{- if .Legacy }}
  leaf_cert:
    content: |
{{ indent 6 .LeafCertPEM }}
  leaf_key:
    content: |
{{ indent 6 .LeafKeyPEM }}
  mesh_ca:
    content: |
{{ indent 6 .MeshCAPEM }}
{{- end }}
`))

// indentBlock prefixes every non-empty line of s with n spaces. Blank lines are
// left empty (not padded) so they don't introduce trailing whitespace and never
// fall below the YAML block-scalar's indentation. Used to embed the multi-line
// Alloy config and PEM blobs under `content: |`.
func indentBlock(n int, s string) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			lines[i] = ""
			continue
		}
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// Legacy reports whether this spec is the mesh-leaf shape. A spec that names
// the node's own key is the node-key shape; anything else is legacy.
func (s CollectorSpec) Legacy() bool {
	return strings.TrimSpace(s.NodeKeyPath) == "" || strings.TrimSpace(s.NodeKeyCertPath) == ""
}

// BuildCollectorCompose renders the self-contained compose YAML for a per-node
// collector: the Alloy River config, plus either a read-only bind of the
// node's own key and certificate (the node-key shape) or the mesh leaf's PEM
// files inline (legacy). Returns an error if the spec is missing anything the
// deployment can't work without.
func BuildCollectorCompose(spec CollectorSpec) (string, error) {
	switch {
	case strings.TrimSpace(spec.NodeID) == "":
		return "", fmt.Errorf("obs collector: NodeID required")
	case strings.TrimSpace(spec.IngressBaseURL) == "":
		return "", fmt.Errorf("obs collector: IngressBaseURL required")
	case strings.TrimSpace(spec.ServerName) == "":
		return "", fmt.Errorf("obs collector: ServerName required")
	}
	if spec.Legacy() {
		switch {
		case strings.TrimSpace(spec.LeafCertPEM) == "":
			return "", fmt.Errorf("obs collector: LeafCertPEM required")
		case strings.TrimSpace(spec.LeafKeyPEM) == "":
			return "", fmt.Errorf("obs collector: LeafKeyPEM required")
		case strings.TrimSpace(spec.MeshCAPEM) == "":
			return "", fmt.Errorf("obs collector: MeshCAPEM required")
		}
	} else if strings.TrimSpace(spec.BusCertPEM) == "" {
		// Fail closed rather than render a collector with no trust anchor:
		// Alloy would fall back to the system roots, which on this image
		// trust nothing the control plane presents.
		return "", fmt.Errorf("obs collector: BusCertPEM required for a node-key collector")
	}
	image := spec.AlloyImage
	if image == "" {
		image = defaultAlloyImage
	}
	// This compose file is rendered per node and handed to an agent to run, so
	// it is the last place the reference can be checked before it becomes a
	// `docker compose up` somewhere else. The controlplane's own stack is
	// gated in NewDockerComposeSupervisor; this is the same rule for the copy
	// that leaves the box (geekdojo/geekdojo-brain#534).
	if err := validateImages(map[string]string{"RASPUTIN_OBS_ALLOY_IMAGE": image}); err != nil {
		return "", fmt.Errorf("obs collector: %w", err)
	}

	// Where the client material lands INSIDE the container, and how the
	// collector is told what to trust. The node-key shape pins the control
	// plane by the bus certificate's exact bytes, carried inline (it is public
	// and the node has no copy of its own); legacy trusts the mesh CA, which
	// rides as a file next to the leaf.
	certPath, keyPath := collectorNodeKeyCertPath, collectorNodeKeyPath
	// %q: one double-quoted Alloy string with the PEM's newlines escaped.
	// Alloy's config language has no heredoc, and a PEM with literal newlines
	// would not parse. The trailing newline is kept so the value is the
	// certificate's exact bytes.
	trust := fmt.Sprintf("      ca_pem      = %q", strings.TrimRight(spec.BusCertPEM, "\n")+"\n")
	if spec.Legacy() {
		certPath, keyPath = collectorLeafCertPath, collectorLeafKeyPath
		trust = fmt.Sprintf("      ca_file     = %q", collectorMeshCAPath)
	}

	base := strings.TrimRight(spec.IngressBaseURL, "/")
	var alloyBuf bytes.Buffer
	if err := collectorAlloyTmpl.Execute(&alloyBuf, map[string]string{
		"NodeID":            spec.NodeID,
		"MetricsIngressURL": base + obsMetricsIngestPath,
		"LogsIngressURL":    base + obsLogsIngestPath,
		"ServerName":        spec.ServerName,
		"ClientCertPath":    certPath,
		"ClientKeyPath":     keyPath,
		"TrustBlock":        trust,
	}); err != nil {
		return "", fmt.Errorf("obs collector: render alloy config: %w", err)
	}

	var composeBuf bytes.Buffer
	if err := collectorComposeTmpl.Execute(&composeBuf, map[string]any{
		"AlloyImage":      image,
		"AlloyConfig":     alloyBuf.String(),
		"Legacy":          spec.Legacy(),
		"LeafCertPEM":     strings.TrimRight(spec.LeafCertPEM, "\n"),
		"LeafKeyPEM":      strings.TrimRight(spec.LeafKeyPEM, "\n"),
		"MeshCAPEM":       strings.TrimRight(spec.MeshCAPEM, "\n"),
		"NodeKeyCertPath": spec.NodeKeyCertPath,
		"NodeKeyPath":     spec.NodeKeyPath,
		"ClientCertPath":  certPath,
		"ClientKeyPath":   keyPath,
	}); err != nil {
		return "", fmt.Errorf("obs collector: render compose: %w", err)
	}
	return composeBuf.String(), nil
}

// Ingress route paths on the api's mTLS listener the collector writes to. Kept
// in sync with the api package's route patterns (obs_ingest.go): metrics
// predate 1.2c, logs are 1.2c. BuildCollectorCompose appends these to the base.
const (
	obsMetricsIngestPath = "/api/obs/ingest"
	obsLogsIngestPath    = "/api/obs/logs/ingest"
)

// DeriveIngressEndpoint builds the collector's mTLS ingress BASE url and TLS
// server_name from the api's canonical public base URL and the ingress bind
// address. Templating from RASPUTIN_PUBLIC_BASE_URL (never a hardcoded
// rasputin.local) keeps collectors forward-compatible with the per-cluster
// discovery-name fix for the two-cluster problem: when that lands, the public
// base URL changes and every collector follows on its next reconcile (§3.10).
//
//	publicBaseURL — e.g. "https://rasputin.local" (RASPUTIN_PUBLIC_BASE_URL).
//	ingressAddr   — the ingress bind, e.g. ":8443" (RASPUTIN_OBS_INGEST_ADDR).
//
// Returns "https://<host>:<ingress-port>" (the builder appends the per-signal
// ingest paths) and server_name = that host. The scheme is always https (the
// ingress is TLS-only); any port on the base URL is dropped for the ingress port.
func DeriveIngressEndpoint(publicBaseURL, ingressAddr string) (baseURL, serverName string, err error) {
	u, err := url.Parse(strings.TrimSpace(publicBaseURL))
	if err != nil {
		return "", "", fmt.Errorf("obs collector: parse public base url %q: %w", publicBaseURL, err)
	}
	host := u.Hostname()
	if host == "" {
		// A bare host with no scheme parses with an empty Hostname(); fall back
		// to the whole trimmed string (minus any :port) as the host.
		host = strings.TrimSpace(publicBaseURL)
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
	}
	if host == "" {
		return "", "", fmt.Errorf("obs collector: no host in public base url %q", publicBaseURL)
	}
	port := strings.TrimPrefix(strings.TrimSpace(ingressAddr), ":")
	if strings.Contains(port, ":") { // form "0.0.0.0:8443" -> take the port
		_, port, _ = strings.Cut(port, ":")
	}
	if port == "" {
		return "", "", fmt.Errorf("obs collector: no port in ingress addr %q", ingressAddr)
	}
	return fmt.Sprintf("https://%s:%s", host, port), host, nil
}
