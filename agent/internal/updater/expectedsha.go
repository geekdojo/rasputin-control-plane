package updater

import (
	"crypto/sha256"
	"fmt"
)

// expectedSHAHexLen is the length of a sha256 rendered as lowercase hex, which
// is the only form the api ever puts in UpdateDownloadCmd.ExpectedSHA256 and
// the only form the post-download compare can match.
const expectedSHAHexLen = sha256.Size * 2

// requireExpectedSHA refuses a download whose command names no usable content
// hash, BEFORE the transfer starts.
//
// Every backend used to guard its compare with `expectedSHA != "" &&
// observed != expectedSHA`, so an empty hash did not fail the download — it
// removed the check. That is a gate an upstream can switch off by omission:
// the one field that decides whether the bytes are compared to anything also
// decided whether they are compared at all, and the quiet outcome was the
// permissive one. Emptiness is now the failure, and it is raised here rather
// than at the compare so a node does not spend half a gigabyte to learn there
// was never anything to check it against.
//
// The shape is checked too, not only emptiness. A value that is not 64
// lowercase hex characters cannot equal the hex digest the backend computes,
// so it was already a guaranteed "sha mismatch" after a full download; saying
// so up front names the real fault instead of making a malformed command look
// like a corrupted artifact. No normalisation happens here on purpose —
// upper-casing a hash to make it match would widen what is accepted, which is
// the opposite of the point.
//
// MIXED FLEETS. An agent carrying this refuses a download from a control plane
// that sends an empty ExpectedSHA256. The api never has: jobs.go fills it from
// the bundle row's content-addressed sha, which is how the blob is named on
// disk and in the URL the same command carries. The refusal is therefore
// reachable only from an api that has been made to emit a command it has no
// legitimate way to produce.
func requireExpectedSHA(bundleID, expectedSHA string) error {
	if expectedSHA == "" {
		return fmt.Errorf("the control plane sent no expected sha256 for bundle %s; this node will not "+
			"install an artifact it cannot check against a stated hash — update the control plane", bundleID)
	}
	if len(expectedSHA) != expectedSHAHexLen || !isLowerHex(expectedSHA) {
		return fmt.Errorf("the control plane sent %q as the expected sha256 for bundle %s, which is not a "+
			"lowercase hex sha256 digest and cannot match any artifact", expectedSHA, bundleID)
	}
	return nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
