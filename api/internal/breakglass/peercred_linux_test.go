//go:build linux

package breakglass

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TC-321-04 (the real reader): SO_PEERCRED on a real Unix socket connection
// reads the connecting process's uid, this test's own.
func TestPeerUID_ReadsTheKernelsUID_TC321_04(t *testing.T) {
	path := filepath.Join(socketDir(t), "p.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan error, 1)
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer func() { _ = c.Close() }()
		}
		done <- err
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	uid, err := PeerUID(c)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("PeerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := PeerUID(&net.TCPConn{}); err == nil {
		t.Error("PeerUID read a uid off a TCP connection")
	}
}
