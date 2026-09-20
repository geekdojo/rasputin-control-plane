package busauth

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		host    string
		enforce bool
		refused bool
	}{
		// Anything but "off" enforces, on any host. The default is the empty
		// value an incomplete seed leaves behind.
		{"unset", "", "0.0.0.0", true, false},
		{"unset on loopback", "", "127.0.0.1", true, false},
		{"enforce", "enforce", "0.0.0.0", true, false},
		{"a typo is not off", "offf", "0.0.0.0", true, false},
		{"OFF is not off", "OFF", "0.0.0.0", true, false},
		{"off with trailing space", " off ", "127.0.0.1", false, false},

		// off is allowed on loopback only.
		{"off on 127.0.0.1", "off", "127.0.0.1", false, false},
		{"off on another 127/8 address", "off", "127.0.0.53", false, false},
		{"off on ::1", "off", "::1", false, false},
		{"off on a bracketed ::1", "off", "[::1]", false, false},
		{"off on localhost", "off", "localhost", false, false},
		{"off on LOCALHOST", "off", "LOCALHOST", false, false},

		// ...and refused everywhere else. Each of these is a bus some other
		// machine can reach.
		{"off on 0.0.0.0", "off", "0.0.0.0", true, true},
		{"off on ::", "off", "::", true, true},
		{"off on a LAN address", "off", "192.168.1.10", true, true},
		{"off on a tailnet address", "off", "100.64.0.3", true, true},
		{"off on a hostname", "off", "rasputin.local", true, true},
		{"off on an empty host", "off", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enforce, err := ResolveEnforcement(tc.value, tc.host)
			if enforce != tc.enforce {
				t.Errorf("enforce = %t, want %t", enforce, tc.enforce)
			}
			switch {
			case tc.refused && err == nil:
				t.Fatal("the unsafe combination was accepted")
			case !tc.refused && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.refused:
				return
			}
			if !errors.Is(err, ErrOffOffLoopback) {
				t.Errorf("error does not wrap ErrOffOffLoopback: %v", err)
			}
			// A refusal that does not say what to change is a refusal an
			// operator works around.
			msg := err.Error()
			for _, want := range []string{EnvEnforce, EnvNATSHost, "127.0.0.1", "reflash"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not mention %q: %s", want, msg)
				}
			}
			// And it must not offer itself as a recovery lever: there is no
			// re-mint path over the bus (geekdojo/geekdojo-brain#511).
			if strings.Contains(msg, "re-mint one") && !strings.Contains(msg, "no way to re-mint one") {
				t.Errorf("the refusal reads as if a token can be re-minted: %s", msg)
			}
		})
	}
}

// A refused start returns enforce=true so a caller that ignored the error
// cannot end up running open — the value is never the unsafe one.
func TestResolveEnforcement_RefusalIsNeverOpen(t *testing.T) {
	enforce, err := ResolveEnforcement("off", "0.0.0.0")
	if err == nil || !enforce {
		t.Fatalf("(%t, %v), want enforcement and a refusal", enforce, err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost", "LocalHost", " 127.0.0.1 ", "::ffff:127.0.0.1"}
	for _, h := range loopback {
		if !IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", h)
		}
	}
	// "localhost." and "localhost.localdomain" are NOT accepted: only the
	// exact reserved name is, because anything else has to be resolved to be
	// judged and the answer can change after this process reads it.
	notLoopback := []string{"", "0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "100.64.0.3",
		"rasputin.local", "localhost.localdomain", "localhost.", "notlocalhost", "8.8.8.8"}
	for _, h := range notLoopback {
		if IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", h)
		}
	}
}
