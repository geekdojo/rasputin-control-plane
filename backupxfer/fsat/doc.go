// Package fsat is the no-symlink filesystem discipline both ends of the
// backup path write and read through: openat(2) with O_NOFOLLOW, one
// component at a time, relative to a directory fd that was itself opened the
// same way, and fstat(2) on every fd before it is trusted to be what the
// caller said it was.
//
// It exists as a package of its own because the discipline was derived twice
// already — once in the agent's quiesce walk (agent/internal/quiesce/
// walk_unix.go, the READ side over a volume a container may still be writing)
// and once in backupxfer's ingest endpoint (the WRITE side under a generation
// directory on a disk the operator owns). The restore path (#291) is a third
// consumer with the most to lose: it is root writing into /var/lib/rasputin
// from an archive on a disk somebody plugged in. A third copy is how three
// paths come to differ in exactly the case that matters, so the write-side
// primitives live here and both backupxfer and the api's restore import them.
//
// The threat these defend against is the same on every path: a symlink
// planted where a name was expected, so that a path-based open lands on
// /etc/shadow, another app's volume, or the mesh CA key under an innocent
// name. A symlink anywhere in a path is ELOOP here, not a redirect, and a
// name that is not the kind of thing the caller expected (a file where a
// directory should be, or the reverse) is refused after the fstat.
//
// Only the root is opened by path. Everything beneath it is fd-relative.
package fsat
