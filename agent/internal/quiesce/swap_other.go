//go:build !linux && !darwin

package quiesce

import (
	"errors"
	"os"
)

// No atomic directory exchange on this platform, and the restore verb
// refuses rather than substituting two renames: the property "the volume
// path always names a whole tree" is the one the verb promises, and a
// platform that cannot keep it does not get a weaker version quietly.
func exchangeDirs(string, string) error {
	return errors.New("no atomic directory exchange on this platform; the restore verb runs on linux")
}

func ownerOf(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
