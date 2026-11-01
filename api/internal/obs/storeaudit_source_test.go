package obs

import (
	"path/filepath"
	"strings"
	"testing"
)

// ----- Secret store audit source (geekdojo/geekdojo-brain#802) -------------

// storeAuditTestLog is a StoreAuditLog for render tests. Rendering never stats
// it.
const storeAuditTestLog = "/var/lib/rasputin/openbao-audit/audit.log"

// storeAuditSup builds a supervisor for the store-audit render tests.
func storeAuditSup(t *testing.T, auditLog string, loki bool) *DockerComposeSupervisor {
	t.Helper()
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:           t.TempDir(),
		ControlPlaneNodeID: "cp-1",
		EnableLoki:         &loki,
		StoreAuditLog:      auditLog,
	})
	if err != nil {
		t.Fatalf("NewDockerComposeSupervisor: %v", err)
	}
	return sup
}

// TC-802-01: with Loki on and StoreAuditLog set, the Alloy config holds the
// store-audit chain: local.file_match with exactly one target, the live
// file's exact path inside the container and job="rasputin-store-audit",
// feeding loki.source.file, feeding loki.process with the JSON and timestamp
// stages, forwarding to loki.write.local.
func TestRenderAlloyConfig_StoreAuditSource(t *testing.T) {
	cfg := renderAlloy(t, storeAuditSup(t, storeAuditTestLog, true))

	match, n := riverBlock(cfg, `local.file_match "store_audit"`)
	if n != 1 || match == "" {
		t.Fatalf("%d local.file_match blocks, want exactly one \"store_audit\"\n%s", n, cfg)
	}
	const target = `{"__path__" = "/var/log/openbao-audit/audit.log", "job" = "rasputin-store-audit"},`
	if strings.Count(match, "__path__") != 1 || !strings.Contains(match, target) {
		t.Errorf("file_match body %q, want exactly the one target %s", match, target)
	}

	src, n := riverBlock(cfg, `loki.source.file "store_audit"`)
	if src == "" {
		t.Fatalf("no loki.source.file \"store_audit\" (%d loki.source.file blocks)\n%s", n, cfg)
	}
	if v, _ := riverAttr(src, "targets"); v != "local.file_match.store_audit.targets" {
		t.Errorf("source targets = %q, want local.file_match.store_audit.targets", v)
	}
	if v, _ := riverAttr(src, "forward_to"); v != "[loki.process.store_audit.receiver]" {
		t.Errorf("source forward_to = %q, want [loki.process.store_audit.receiver]", v)
	}

	proc, _ := riverBlock(cfg, `loki.process "store_audit"`)
	if proc == "" {
		t.Fatalf("no loki.process \"store_audit\"\n%s", cfg)
	}
	if v, _ := riverAttr(proc, "forward_to"); v != "[loki.write.local.receiver]" {
		t.Errorf("process forward_to = %q, want [loki.write.local.receiver]", v)
	}
	js, _ := riverBlock(proc, "stage.json")
	if v, _ := riverAttr(js, "expressions"); v != `{ts = "time"}` {
		t.Errorf("stage.json expressions = %q, want {ts = \"time\"}", v)
	}
	ts, _ := riverBlock(proc, "stage.timestamp")
	if v, _ := riverAttr(ts, "source"); v != `"ts"` {
		t.Errorf("stage.timestamp source = %q, want \"ts\"", v)
	}
	if v, _ := riverAttr(ts, "format"); v != `"RFC3339Nano"` {
		t.Errorf("stage.timestamp format = %q, want \"RFC3339Nano\"", v)
	}

	// No glob anywhere in the source: a rotated copy must never match.
	if strings.Contains(match+src, "*") {
		t.Errorf("store-audit source holds a glob\n%s\n%s", match, src)
	}
}

// TC-802-02: with Loki off (StoreAuditLog set) and with StoreAuditLog empty
// (Loki on), neither the store_audit block nor any openbao-audit mount is
// rendered.
func TestRenderStoreAudit_AbsentWhenItCannotRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		auditLog string
		loki     bool
	}{
		{"Loki off, StoreAuditLog set", storeAuditTestLog, false},
		{"Loki on, StoreAuditLog empty", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup := storeAuditSup(t, tc.auditLog, tc.loki)
			cfg := renderAlloy(t, sup)
			compose, err := sup.renderCompose()
			if err != nil {
				t.Fatalf("render compose: %v", err)
			}
			for name, body := range map[string]string{"alloy config": cfg, "compose": string(compose)} {
				for _, absent := range []string{"store_audit", "openbao-audit"} {
					if strings.Contains(body, absent) {
						t.Errorf("%s holds %q\n%s", name, absent, body)
					}
				}
			}
		})
	}
}

// TC-802-03: with the source on, Alloy mounts the audit file's parent
// directory read-only at /var/log/openbao-audit, and never the file itself.
func TestRenderCompose_StoreAuditDirMountReadOnly(t *testing.T) {
	svc := renderAlloyService(t, storeAuditSup(t, storeAuditTestLog, true))
	var mounts []string
	for _, v := range svc.Volumes {
		if strings.HasSuffix(strings.Split(v, ":")[0], "audit.log") {
			t.Errorf("volume %q mounts the audit file itself", v)
		}
		if strings.Contains(v, "openbao-audit") {
			mounts = append(mounts, v)
		}
	}
	want := filepath.Dir(storeAuditTestLog) + ":" + storeAuditContainerDir + ":ro"
	if len(mounts) != 1 || mounts[0] != want {
		t.Errorf("openbao-audit volumes %v, want exactly [%s]", mounts, want)
	}
}

// TC-802-04: a relative StoreAuditLog is made absolute, so compose reads the
// mount source as a bind mount and not a named volume.
func TestNewDockerComposeSupervisor_MakesStoreAuditLogAbsolute(t *testing.T) {
	sup := storeAuditSup(t, filepath.Join("data", "openbao-audit", "audit.log"), true)
	if got := sup.StoreAuditLog(); !filepath.IsAbs(got) {
		t.Errorf("StoreAuditLog = %q, want absolute", got)
	}
	for _, v := range renderAlloyService(t, sup).Volumes {
		src, rest, _ := strings.Cut(v, ":")
		if strings.HasPrefix(rest, storeAuditContainerDir) {
			if !strings.HasPrefix(src, "/") || !strings.HasSuffix(src, filepath.Join("data", "openbao-audit")) {
				t.Errorf("mount source %q, want an absolute path ending in data/openbao-audit", src)
			}
			return
		}
	}
	t.Errorf("no %s mount in %v", storeAuditContainerDir, renderAlloyService(t, sup).Volumes)
}
