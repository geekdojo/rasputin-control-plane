package system

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The agent has exactly one function that restarts the node, and this test is
// what keeps it that way. It reads every non-test Go file in the agent module
// and fails if anything other than reboot.go could restart or power off the
// machine: a second implementation would reboot without the announcement, the
// mute and the log lines every other reboot has, which is the defect
// geekdojo/geekdojo-brain#616 was about.
//
// If this fails on code you just wrote, do not add your file to the allow
// list: call (*Rebooter).Reboot, and add a RebootMode if you need one.
func TestTheAgentHasExactlyOneRebootImplementation(t *testing.T) {
	const only = "internal/system/reboot.go"
	forbidden := []*regexp.Regexp{
		// exec of a command that restarts or powers off the machine
		regexp.MustCompile(`exec\.Command(Context)?\((\s*ctx\s*,)?\s*"(/[a-z/]*/)?(reboot|shutdown|poweroff|halt|kexec)"`),
		regexp.MustCompile(`"systemctl"\s*,\s*"(reboot|poweroff|halt|kexec|soft-reboot)"`),
		regexp.MustCompile(`"(busctl|dbus-send|loginctl)"[^\n]*(Reboot|PowerOff)`),
		// the syscall itself
		regexp.MustCompile(`\b(syscall|unix)\.Reboot\(`),
		regexp.MustCompile(`LINUX_REBOOT_`),
		// the Raspberry Pi trial-boot argument
		regexp.MustCompile(`0 tryboot`),
		// the kernel's sysrq trigger
		regexp.MustCompile(`sysrq-trigger`),
	}

	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot find the agent module root from %s: %v", root, err)
	}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == only {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, re := range forbidden {
				if re.MatchString(line) {
					t.Errorf("%s:%d restarts the node outside the one reboot function (%s):\n\t%s",
						rel, i+1, only, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked < 20 {
		t.Fatalf("only %d files were checked; the walk is not seeing the agent module", checked)
	}
}
