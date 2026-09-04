package proto

import (
	"regexp"
	"testing"
)

// Every entry is bare CalVer — the shape the agent reports itself under —
// so inventory's comparison never trips on a stray "v".
func TestVerbMinAgentVersionsAreBareCalVer(t *testing.T) {
	calver := regexp.MustCompile(`^\d{4}\.\d{1,2}\.\d+(?:-dev\.\d+)?$`)
	for verb, v := range verbMinAgentVersion {
		if !calver.MatchString(v) {
			t.Errorf("%s: %q is not bare CalVer (YYYY.MM.PATCH[-dev.N])", verb, v)
		}
	}
}

// The verbs the two misdiagnosed sites send are recorded, and a verb nobody
// recorded says so rather than inventing a floor.
func TestVerbMinAgentVersionLookup(t *testing.T) {
	for _, verb := range []string{"storage.backup_stage_volume", "docker.volumes.list", "docker.volumes.remove", "storage.backup_restore_volume"} {
		if _, ok := VerbMinAgentVersion(verb); !ok {
			t.Errorf("%s has no minimum agent version recorded", verb)
		}
	}
	if v, ok := VerbMinAgentVersion("diag.ping"); ok || v != "" {
		t.Errorf("diag.ping: got (%q, %v), want unrecorded", v, ok)
	}
}

// Every subject the storage and volume builders mint takes apart into the
// node and the verb that was sent, so a caller holding only the subject can
// look the verb up.
func TestCmdSubjectVerbRoundTrips(t *testing.T) {
	cases := map[string]string{
		BackupStageVolumeSubject("e3bench-compute1"): "storage.backup_stage_volume",
		AppVolumesListSubject("n1"):                  "docker.volumes.list",
		AppVolumesRemoveSubject("n1"):                "docker.volumes.remove",
		BackupRestoreVolumeSubject("compute1"):       "storage.backup_restore_volume",
		NodeCmdSubject("n1", "diag.ping"):            "diag.ping",
	}
	for subject, want := range cases {
		nodeID, verb, ok := CmdSubjectVerb(subject)
		if !ok || verb != want || nodeID == "" {
			t.Errorf("%s: got (%q, %q, %v), want verb %q", subject, nodeID, verb, ok, want)
		}
	}
	for _, bad := range []string{"", "rasputin.node.n1.heartbeat", "rasputin.node.n1.cmd.", "rasputin.node..cmd.diag.ping", "rasputin.job.j1.events"} {
		if _, _, ok := CmdSubjectVerb(bad); ok {
			t.Errorf("%q parsed as a cmd subject", bad)
		}
	}
}
