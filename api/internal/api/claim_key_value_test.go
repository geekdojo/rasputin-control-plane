package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TC-825-35: POST /api/backup/targets with an archive key missing either
// wrapping answers 400 and stages nothing: the key is converted (and refused)
// once, by storage.NewArchiveKey, before any job exists.
func TestClaimBackupTarget_RefusesAKeyMissingAWrapping(t *testing.T) {
	for name, wrappings := range map[string]string{
		"no recovery wrapping":   `"wrappedByPassphrase":"SENTINEL-PP"`,
		"no passphrase wrapping": `"wrappedByRecoveryCode":"SENTINEL-RC"`,
	} {
		t.Run(name, func(t *testing.T) {
			s, backup, _ := storageTestServer(t)
			rec := postClaim(t, s, `{"nodeId":"`+storageTestNode+`","devicePath":"/dev/sdb","fingerprint":"fp",`+
				`"archiveKey":{"keyId":"ak-1","publicKey":"AAAA",`+wrappings+`}}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "archiveKey is incomplete") {
				t.Errorf("body = %s, want the incomplete-key refusal", rec.Body.String())
			}
			if staged, err := backup.StagedClaimKeyJobs(context.Background()); err != nil || len(staged) != 0 {
				t.Errorf("staged keys = %v (err %v), want none", staged, err)
			}
			if list, _ := s.store.ListJobs(context.Background(), 10); len(list) != 0 {
				t.Errorf("a refused key created %d job(s)", len(list))
			}
		})
	}
}
