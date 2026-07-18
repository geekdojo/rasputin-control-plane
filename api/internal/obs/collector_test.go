package obs

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Multi-line PEM-shaped blobs — the point is to prove the inline-content
// indentation round-trips a multi-line value byte-for-byte through the YAML
// block scalar, which is the whole risk of the inline-configs approach.
const (
	testLeafCert = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+2FByte\nc2Vjb25kbGluZQ==\n-----END CERTIFICATE-----"
	testLeafKey  = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIByteKey\n-----END EC PRIVATE KEY-----"
	testMeshCA   = "-----BEGIN CERTIFICATE-----\nMIICAcaByteBlob\n-----END CERTIFICATE-----"
)

func validCollectorSpec() CollectorSpec {
	return CollectorSpec{
		NodeID:      "c02",
		IngressURL:  "https://rasputin.local:8443/api/obs/ingest",
		ServerName:  "rasputin.local",
		LeafCertPEM: testLeafCert,
		LeafKeyPEM:  testLeafKey,
		MeshCAPEM:   testMeshCA,
	}
}

// composeFile is the subset of the compose schema the tests assert on.
type composeFile struct {
	Services map[string]struct {
		Image       string   `yaml:"image"`
		NetworkMode string   `yaml:"network_mode"`
		Command     []string `yaml:"command"`
		Volumes     []string `yaml:"volumes"`
		Configs     []struct {
			Source string `yaml:"source"`
			Target string `yaml:"target"`
		} `yaml:"configs"`
	} `yaml:"services"`
	Configs map[string]struct {
		Content string `yaml:"content"`
	} `yaml:"configs"`
}

func TestBuildCollectorCompose_WellFormed(t *testing.T) {
	out, err := BuildCollectorCompose(validCollectorSpec())
	if err != nil {
		t.Fatalf("BuildCollectorCompose: %v", err)
	}

	// The linchpin: it must parse as valid YAML. A bad inline-content indent
	// would fail here or silently corrupt the cert blobs below.
	var cf composeFile
	if err := yaml.Unmarshal([]byte(out), &cf); err != nil {
		t.Fatalf("generated compose is not valid YAML: %v\n---\n%s", err, out)
	}

	svc, ok := cf.Services["alloy"]
	if !ok {
		t.Fatalf("no alloy service in compose:\n%s", out)
	}
	if svc.NetworkMode != "host" {
		t.Errorf("network_mode: got %q, want host (mDNS resolution needs it)", svc.NetworkMode)
	}
	if svc.Image != defaultAlloyImage {
		t.Errorf("image: got %q, want %q", svc.Image, defaultAlloyImage)
	}

	// cAdvisor host access + fixed appliance data-root (§3.9b).
	wantVols := []string{
		"/var/run/docker.sock:/var/run/docker.sock:ro",
		"/sys:/sys:ro",
		collectorDataRoot + ":" + collectorDataRoot + ":ro",
	}
	for _, v := range wantVols {
		if !containsStr(svc.Volumes, v) {
			t.Errorf("missing volume %q; got %v", v, svc.Volumes)
		}
	}

	// The four inline configs map to their in-container targets.
	wantTargets := map[string]string{
		"alloy_config": collectorConfigPath,
		"leaf_cert":    collectorLeafCertPath,
		"leaf_key":     collectorLeafKeyPath,
		"mesh_ca":      collectorMeshCAPath,
	}
	for src, target := range wantTargets {
		found := false
		for _, c := range svc.Configs {
			if c.Source == src {
				found = true
				if c.Target != target {
					t.Errorf("config %q target: got %q, want %q", src, c.Target, target)
				}
			}
		}
		if !found {
			t.Errorf("service does not mount config %q", src)
		}
	}

	// The cert blobs must survive the block scalar byte-for-byte (clip
	// chomping leaves a single trailing newline, hence TrimRight).
	certChecks := map[string]string{
		"leaf_cert": testLeafCert,
		"leaf_key":  testLeafKey,
		"mesh_ca":   testMeshCA,
	}
	for name, want := range certChecks {
		got := strings.TrimRight(cf.Configs[name].Content, "\n")
		if got != want {
			t.Errorf("config %q content corrupted:\n got: %q\nwant: %q", name, got, want)
		}
	}

	// The embedded Alloy River config carries the node label, the ingress
	// endpoint, and the mTLS cert paths.
	alloy := cf.Configs["alloy_config"].Content
	for _, want := range []string{
		`node_id = "c02"`,
		`url = "https://rasputin.local:8443/api/obs/ingest"`,
		`server_name = "rasputin.local"`,
		`cert_file   = "` + collectorLeafCertPath + `"`,
		`key_file    = "` + collectorLeafKeyPath + `"`,
		`ca_file     = "` + collectorMeshCAPath + `"`,
		"docker_only = true",
	} {
		if !strings.Contains(alloy, want) {
			t.Errorf("alloy config missing %q\n---\n%s", want, alloy)
		}
	}
}

func TestBuildCollectorCompose_Validation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CollectorSpec)
	}{
		{"missing NodeID", func(s *CollectorSpec) { s.NodeID = "" }},
		{"missing IngressURL", func(s *CollectorSpec) { s.IngressURL = "" }},
		{"missing ServerName", func(s *CollectorSpec) { s.ServerName = "" }},
		{"missing LeafCertPEM", func(s *CollectorSpec) { s.LeafCertPEM = "" }},
		{"missing LeafKeyPEM", func(s *CollectorSpec) { s.LeafKeyPEM = "" }},
		{"missing MeshCAPEM", func(s *CollectorSpec) { s.MeshCAPEM = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := validCollectorSpec()
			tt.mutate(&spec)
			if _, err := BuildCollectorCompose(spec); err == nil {
				t.Fatalf("expected an error for %s, got nil", tt.name)
			}
		})
	}
}

func TestDeriveIngressEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		ingressAddr string
		wantURL     string
		wantServer  string
		wantErr     bool
	}{
		{"canonical https base", "https://rasputin.local", ":8443",
			"https://rasputin.local:8443/api/obs/ingest", "rasputin.local", false},
		{"base carries a port, ingress port wins", "https://rasputin.local:443", ":8443",
			"https://rasputin.local:8443/api/obs/ingest", "rasputin.local", false},
		{"dev http base is forced to https", "http://localhost:8080", ":8443",
			"https://localhost:8443/api/obs/ingest", "localhost", false},
		{"bare host, no scheme", "rasputin.local", ":8443",
			"https://rasputin.local:8443/api/obs/ingest", "rasputin.local", false},
		{"ingress addr with explicit interface", "https://rasputin.local", "0.0.0.0:8443",
			"https://rasputin.local:8443/api/obs/ingest", "rasputin.local", false},
		{"empty base url", "", ":8443", "", "", true},
		{"ingress addr with no port", "https://rasputin.local", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotServer, err := DeriveIngressEndpoint(tt.baseURL, tt.ingressAddr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got url=%q server=%q", gotURL, gotServer)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotURL != tt.wantURL {
				t.Errorf("url: got %q, want %q", gotURL, tt.wantURL)
			}
			if gotServer != tt.wantServer {
				t.Errorf("server_name: got %q, want %q", gotServer, tt.wantServer)
			}
		})
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
