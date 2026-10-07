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
	for key, v := range metadataMinAgentVersion {
		if !calver.MatchString(v) {
			t.Errorf("metadata %s: %q is not bare CalVer (YYYY.MM.PATCH[-dev.N])", key, v)
		}
	}
	for name, v := range map[string]string{
		"StorageInspectProbeMinAgentVersion": StorageInspectProbeMinAgentVersion,
		"MeshEnrollDeadlineMinAgentVersion":  MeshEnrollDeadlineMinAgentVersion,
		"RestoreReplayMinAgentVersion":       RestoreReplayMinAgentVersion,
		"StorageClaimPurposeMinAgentVersion": StorageClaimPurposeMinAgentVersion,
	} {
		if !calver.MatchString(v) {
			t.Errorf("%s: %q is not bare CalVer (YYYY.MM.PATCH[-dev.N])", name, v)
		}
	}
}

// The metadata keys a consumer acts on have a floor, so a silent node can be
// told apart from one whose agent never heard of the key.
//
// TC-539-09: tokenSource has no floor any more — its emitter and its cutover
// went with the agent's environment token fallback
// (geekdojo/geekdojo-brain#539) — and the two floors that remain are bare
// CalVer strings.
func TestMetadataMinAgentVersionLookup(t *testing.T) {
	calver := regexp.MustCompile(`^\d{4}\.\d{1,2}\.\d+(?:-dev\.\d+)?$`)
	for _, key := range []string{MetadataTrustFingerprint, MetadataNodeKeys} {
		v, ok := MetadataMinAgentVersion(key)
		if !ok {
			t.Errorf("%s has no minimum agent version recorded", key)
		}
		if !calver.MatchString(v) {
			t.Errorf("%s: floor %q is not bare CalVer", key, v)
		}
	}
	if v, ok := MetadataMinAgentVersion("tokenSource"); ok || v != "" {
		t.Errorf("tokenSource: got (%q, %v), want no floor", v, ok)
	}
	if v, ok := MetadataMinAgentVersion("primaryLanCidr"); ok || v != "" {
		t.Errorf("primaryLanCidr: got (%q, %v), want unrecorded", v, ok)
	}
}

// The verbs the two misdiagnosed sites send are recorded, and a verb nobody
// recorded says so rather than inventing a floor.
func TestVerbMinAgentVersionLookup(t *testing.T) {
	for _, verb := range []string{"storage.backup_stage_volume", "docker.volumes.list", "docker.volumes.remove", "storage.backup_restore_volume", "docker.pull", "docker.volumes.check", "docker.volumes.drop", ConsoleRootHashVerb} {
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
		AppPullSubject("n1"):                         "docker.pull",
		AppVolumesCheckSubject("n1"):                 "docker.volumes.check",
		AppVolumesDropSubject("n1"):                  "docker.volumes.drop",
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

// TC-517-14: the plaintext ladder's verb and metadata keys are gone from the
// floor tables, so nothing reads an agent's silence on them as a fault.
func TestLadderKeysHaveNoFloor(t *testing.T) {
	if v, ok := VerbMinAgentVersion("bus.pin"); ok {
		t.Errorf("bus.pin still has a floor %q", v)
	}
	for _, key := range []string{"busTls", "httpsPinned"} {
		if v, ok := MetadataMinAgentVersion(key); ok {
			t.Errorf("metadata key %s still has a floor %q", key, v)
		}
	}
}
