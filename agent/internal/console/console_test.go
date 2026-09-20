package console

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// A real crypt(3) SHA-512 hash (openssl passwd -6 -salt saltstring
// 'Hello world!'), byte-identical to BusyBox 1.37's mkpasswd.
const testHash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"

const otherHash = "$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"

// The form the api actually mints (console.CryptRounds = 100000). BusyBox
// 1.37 and glibc produce this byte for byte, and the firewall image's
// set-root-hash accepts it — checked 2026-09-19. An agent that refused it
// would fail every node the moment the round count moved.
const roundsHash = "$6$rounds=100000$0123456789abcdef$iJ7fHUuAH7szYrYSsd9VSIo1lThtOcStIyubkK8vpm1ghu1.q5O4I1sN5Ci3sND5foG/iO89FuDGxs1JHvMFs/"

func writeShadow(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rootLine(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "root:") {
			return strings.Split(line, ":")
		}
	}
	t.Fatalf("no root line in %s:\n%s", path, raw)
	return nil
}

// The OpenWrt shape: root has an EMPTY password field, which is what
// decision #558 is closing.
func TestApplyRootHashReplacesAnEmptyPassword(t *testing.T) {
	path := writeShadow(t, "root::0:0:99999:7:::\ndaemon:*:0:0:99999:7:::\nnobody:*:0:0:99999:7:::\n")
	changed, err := ApplyRootHash(path, testHash)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed=false for a shadow file that held no password")
	}
	f := rootLine(t, path)
	if f[1] != testHash {
		t.Fatalf("root password field is %q", f[1])
	}
	// The ageing fields the image chose are untouched apart from last-change.
	if want := strconv.FormatInt(time.Now().UTC().Unix()/86400, 10); f[2] != want {
		t.Errorf("last-change field is %q, want %q", f[2], want)
	}
	if strings.Join(f[3:], ":") != "0:99999:7:::" {
		t.Errorf("the ageing policy changed: %q", strings.Join(f[3:], ":"))
	}
	// No other account was touched.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "daemon:*:0:0:99999:7:::") || !strings.Contains(string(raw), "nobody:*:0:0:99999:7:::") {
		t.Errorf("another account's entry changed:\n%s", raw)
	}
}

// The form the control plane mints today: crypt's rounds= spelling.
func TestApplyRootHashAcceptsTheRoundsForm(t *testing.T) {
	path := writeShadow(t, "root::0:0:99999:7:::\n")
	changed, err := ApplyRootHash(path, roundsHash)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed=false")
	}
	if got := rootLine(t, path)[1]; got != roundsHash {
		t.Fatalf("root password field is %q", got)
	}
	// And it is idempotent in that form too.
	changed, err = ApplyRootHash(path, roundsHash)
	if err != nil || changed {
		t.Fatalf("re-apply: changed=%v err=%v", changed, err)
	}
}

// The OS shape: root already has a hash, from the image.
func TestApplyRootHashReplacesABakedHash(t *testing.T) {
	path := writeShadow(t, "root:"+otherHash+":19000:0:99999:7:::\n")
	changed, err := ApplyRootHash(path, testHash)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed=false when the stored hash differed")
	}
	if got := rootLine(t, path)[1]; got != testHash {
		t.Fatalf("root password field is %q", got)
	}
}

// Idempotent: a re-run of the push job must not rewrite the file.
func TestApplyRootHashIsIdempotent(t *testing.T) {
	path := writeShadow(t, "root:"+testHash+":19000:0:99999:7:::\n")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ApplyRootHash(path, testHash)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("changed=true for a node that already held this hash")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("the shadow file was rewritten for an unchanged hash")
	}
	if rootLine(t, path)[2] != "19000" {
		t.Error("the last-change field moved for an unchanged hash")
	}
}

func TestApplyRootHashKeepsTheFileMode(t *testing.T) {
	path := writeShadow(t, "root::0:0:99999:7:::\n")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRootHash(path, testHash); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode is %#o, want the file's original 0640", got)
	}
	// And nothing world-readable is left behind in the directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d files left in the directory, want just the shadow file", len(entries))
	}
}

func TestApplyRootHashRefusals(t *testing.T) {
	t.Run("malformed hash", func(t *testing.T) {
		path := writeShadow(t, "root::0:0:99999:7:::\n")
		if _, err := ApplyRootHash(path, "not-a-hash"); !errors.Is(err, proto.ErrConsoleRootHashForm) {
			t.Fatalf("err = %v, want a form refusal", err)
		}
		if got := rootLine(t, path)[1]; got != "" {
			t.Fatalf("the file was written anyway: %q", got)
		}
	})
	t.Run("no root entry", func(t *testing.T) {
		path := writeShadow(t, "daemon:*:0:0:99999:7:::\n")
		if _, err := ApplyRootHash(path, testHash); !errors.Is(err, ErrNoRootEntry) {
			t.Fatalf("err = %v, want ErrNoRootEntry", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := ApplyRootHash(filepath.Join(t.TempDir(), "nope"), testHash); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("err = %v, want a not-exist error", err)
		}
	})
}

// Concurrent deliveries must not lose each other's write.
func TestApplyRootHashUnderConcurrentDeliveries(t *testing.T) {
	path := writeShadow(t, "root::0:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n")
	h := NewHandler("n1", path, "/nonexistent/set-root-hash")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := testHash
			if i%2 == 0 {
				hash = otherHash
			}
			_ = h.apply(proto.ConsoleRootHashCmd{Hash: hash, HashID: proto.ConsoleRootHashID(hash)})
		}(i)
	}
	wg.Wait()
	f := rootLine(t, path)
	if f[1] != testHash && f[1] != otherHash {
		t.Fatalf("the root entry is neither delivered hash: %q", f[1])
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), "root:") != 1 || !strings.Contains(string(raw), "daemon:*") {
		t.Fatalf("the file was corrupted:\n%s", raw)
	}
}

// The ack is the control plane's only evidence, so it must be honest and
// must never carry the hash.
func TestHandlerAck(t *testing.T) {
	cases := []struct {
		name       string
		shadow     string
		hash       string
		wantOK     bool
		wantChange bool
		wantDetail string
	}{
		{"applies", "root::0:0:99999:7:::\n", testHash, true, true, ""},
		{"already holds it", "root:" + testHash + ":1:0:99999:7:::\n", testHash, true, false, ""},
		{"no root entry", "daemon:*:0:0:99999:7:::\n", testHash, false, false, "no root entry"},
		{"malformed hash", "root::0:0:99999:7:::\n", "$1$x$y", false, false, "refusing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeShadow(t, tc.shadow)
			h := NewHandler("n1", path, "/nonexistent/set-root-hash")
			ack := h.apply(proto.ConsoleRootHashCmd{Hash: tc.hash, HashID: proto.ConsoleRootHashID(tc.hash)})
			if ack.OK != tc.wantOK {
				t.Fatalf("OK = %v, want %v (detail %q)", ack.OK, tc.wantOK, ack.Detail)
			}
			if ack.Changed != tc.wantChange {
				t.Errorf("Changed = %v, want %v", ack.Changed, tc.wantChange)
			}
			if ack.NodeID != "n1" {
				t.Errorf("NodeID = %q", ack.NodeID)
			}
			if !tc.wantOK {
				if ack.Detail == "" {
					t.Error("a refusal with no reason — #558 requires one")
				}
				if !strings.Contains(ack.Detail, tc.wantDetail) {
					t.Errorf("detail %q does not mention %q", ack.Detail, tc.wantDetail)
				}
			}
			// The ack is the control plane's record, and the control
			// plane writes it into a step result the jobs API serves
			// unredacted. It must name the password, never carry it.
			// (A refusal quotes the FORM a hash must take, which is a
			// constant, so the check is for hash VALUES.)
			raw, err := json.Marshal(ack)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{tc.hash, testHash, otherHash} {
				if len(secret) > 20 && strings.Contains(string(raw), secret) {
					t.Fatalf("the ack carries a hash: %s", raw)
				}
			}
			for _, digest := range []string{testHash, otherHash} {
				if d := digest[strings.LastIndex(digest, "$")+1:]; strings.Contains(string(raw), d) {
					t.Fatalf("the ack carries a hash digest: %s", raw)
				}
			}
		})
	}
}

// A refused delivery leaves the file exactly as it was.
func TestHandlerRefusalLeavesTheFileAlone(t *testing.T) {
	const body = "root:" + otherHash + ":19000:0:99999:7:::\n"
	path := writeShadow(t, body)
	h := NewHandler("n1", path, "/nonexistent/set-root-hash")
	ack := h.apply(proto.ConsoleRootHashCmd{Hash: "$6$short$abc"})
	if ack.OK {
		t.Fatal("a malformed hash was accepted")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != body {
		t.Fatalf("the file changed:\n%s", raw)
	}
}

func TestShadowPathFromEnv(t *testing.T) {
	if got := ShadowPathFromEnv(); got != DefaultShadowPath {
		t.Fatalf("with no override: %q", got)
	}
	t.Setenv("RASPUTIN_SHADOW_FILE", "/tmp/x")
	if got := ShadowPathFromEnv(); got != "/tmp/x" {
		t.Fatalf("with an override: %q", got)
	}
	if h := NewHandler("n1", "", ""); h.shadowPath != DefaultShadowPath || h.helperPath != HelperPath {
		t.Fatalf("empty paths should default: %q %q", h.shadowPath, h.helperPath)
	}
	t.Setenv("RASPUTIN_SET_ROOT_HASH", "/tmp/helper")
	if got := HelperPathFromEnv(); got != "/tmp/helper" {
		t.Fatalf("helper override: %q", got)
	}
}
