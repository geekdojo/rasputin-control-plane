//go:build linux

package bmc

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// openPTY returns a pty master fd and the slave path — a real tty the
// termios port code can be exercised against on CI.
func openPTY(t *testing.T) (int, string) {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open ptmx: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(master) })
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("ptsname: %v", err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", n)
}

func TestOpenBitScopePort_NoSuchDevice(t *testing.T) {
	if _, err := openBitScopePort("/dev/definitely-not-a-tty"); err == nil {
		t.Fatal("expected error for missing device")
	}
}

func TestOpenBitScopePort_NotATTY(t *testing.T) {
	// A regular file opens but refuses termios — the driver must fail
	// loudly rather than run against a non-serial path.
	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := openBitScopePort(f.Name()); err == nil {
		t.Fatal("expected termios error for a regular file")
	}
}

func TestLinuxBusPort_PTYRoundTrip(t *testing.T) {
	master, slave := openPTY(t)
	port, err := openBitScopePort(slave)
	if err != nil {
		t.Fatalf("openBitScopePort(%s): %v", slave, err)
	}
	defer port.Close()

	// master → port (the "BMC replies" direction)
	if _, err := unix.Write(master, []byte("ENABLED\r\n")); err != nil {
		t.Fatalf("master write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := port.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("port read: n=%d err=%v", n, err)
	}
	if string(buf[:n])[0] != 'E' {
		t.Errorf("port read: %q", buf[:n])
	}

	// port → master (the "issue a verb" direction)
	if _, err := port.Write([]byte("01|=")); err != nil {
		t.Fatalf("port write: %v", err)
	}
	n, err = unix.Read(master, buf)
	if err != nil || string(buf[:n]) != "01|=" {
		t.Errorf("master read: %q err=%v", buf[:n], err)
	}

	if err := port.DrainInput(); err != nil {
		t.Errorf("DrainInput: %v", err)
	}
}
