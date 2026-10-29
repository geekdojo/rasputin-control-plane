package updater

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const blockInfoWithESP = `/dev/nvme0n1p1: UUID="1234-ABCD" LABEL="RASPUTINEFI" VERSION="FAT16" TYPE="vfat"
/dev/nvme0n1p2: UUID="ab" VERSION="4.0" MOUNT="/rom" TYPE="squashfs"
`

// fakeRunner stands in for mount, umount, sync and block info.
type fakeRunner struct {
	cmds  []string
	fails map[string]error // keyed by command name
}

func (r *fakeRunner) run(name string, args ...string) ([]byte, error) {
	r.cmds = append(r.cmds, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if err := r.fails[name]; err != nil {
		return []byte(name + ": target is busy"), err
	}
	if name == "block" {
		return []byte(blockInfoWithESP), nil
	}
	return nil, nil
}

// noStdLog fails the test if anything is written through the standard log
// package while it runs: the media logs only through its injected logger.
func noStdLog(t *testing.T) {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(prev)
		log.SetFlags(flags)
		if buf.Len() != 0 {
			t.Errorf("wrote through the standard log package: %q", buf.String())
		}
	})
}

func TestOpenWrtBootMedia_WithESPMountsRunsAndUnmounts(t *testing.T) {
	noStdLog(t)
	r := &fakeRunner{}
	m, err := newOpenWrtBootMedia(discardLogger(), r.run)
	if err != nil {
		t.Fatal(err)
	}
	var mnt string
	if err := m.WithESP(func(root string) error { mnt = root; return nil }); err != nil {
		t.Fatalf("WithESP: %v", err)
	}
	want := []string{"block info", "mount -t vfat -o rw,noatime /dev/nvme0n1p1 " + mnt, "sync", "umount " + mnt}
	if strings.Join(r.cmds, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(r.cmds, "\n"), strings.Join(want, "\n"))
	}
	if _, err := os.Stat(mnt); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("mount point %s left behind after a clean umount", mnt)
	}
}

// TC-888-08 (F-888-04): a failed umount is returned, wrapped and joined with
// fn's error, and logged through the injected logger. The still-mounted ESP's
// files are never deleted with the mount point.
func TestOpenWrtBootMedia_UmountFailureIsReturnedAndLogged(t *testing.T) {
	noStdLog(t)
	umountErr := errors.New("exit status 32")
	r := &fakeRunner{fails: map[string]error{"umount": umountErr}}
	logs := &logCapture{}
	m, err := newOpenWrtBootMedia(logs.logger(), r.run)
	if err != nil {
		t.Fatal(err)
	}
	fnErr := errors.New("write boot/vmlinuz-B.new: no space left on device")
	var mnt string
	err = m.WithESP(func(root string) error {
		mnt = root
		writeFile(t, filepath.Join(root, "boot", "vmlinuz-A"), []byte("A"))
		return fnErr
	})
	t.Cleanup(func() { os.RemoveAll(mnt) })
	if !errors.Is(err, fnErr) || !errors.Is(err, umountErr) {
		t.Fatalf("err = %v, want fn's error joined with the umount error", err)
	}
	for _, want := range []string{"ESP /dev/nvme0n1p1", "umount /dev/nvme0n1p1 from " + mnt} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(mnt, "boot", "vmlinuz-A")); err != nil {
		t.Errorf("a file on the still-mounted ESP was removed: %v", err)
	}
	var found bool
	for _, rec := range logs.records(t) {
		if rec["level"] == "ERROR" && rec["device"] == "/dev/nvme0n1p1" && rec["mountpoint"] == mnt {
			found = true
		}
	}
	if !found {
		t.Errorf("no ERROR record naming the device and mount point: %v", logs.records(t))
	}

	// A failed umount alone, after a successful fn, is still an error.
	if err := m.WithESP(func(string) error { return nil }); !errors.Is(err, umountErr) {
		t.Errorf("err = %v, want the umount error when fn succeeded", err)
	}
}

func TestOpenWrtBootMedia_MountFailureNeverRunsFn(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *fakeRunner
		want string
	}{
		{"mount", &fakeRunner{fails: map[string]error{"mount": errors.New("exit status 255")}}, "mount ESP /dev/nvme0n1p1"},
		{"block info", &fakeRunner{fails: map[string]error{"block": errors.New("exit status 1")}}, "resolve ESP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newOpenWrtBootMedia(discardLogger(), tc.r.run)
			ran := false
			err := m.WithESP(func(string) error { ran = true; return nil })
			if err == nil || ran || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, fn ran = %v; want %q and fn not run", err, ran, tc.want)
			}
		})
	}
	t.Run("no ESP listed", func(t *testing.T) {
		m, _ := newOpenWrtBootMedia(discardLogger(), func(name string, _ ...string) ([]byte, error) { return nil, nil })
		if err := m.WithESP(func(string) error { t.Error("fn ran"); return nil }); err == nil {
			t.Error("WithESP succeeded with no ESP in block info")
		}
	})
}

func TestUnixModuleLoader_MissingFileIsAnErrorNamingIt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vfat.ko")
	if err := (UnixModuleLoader{}).Load(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("Load(missing) = %v, want an error naming %s", err, p)
	}
}
