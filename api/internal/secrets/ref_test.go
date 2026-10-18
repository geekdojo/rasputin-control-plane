package secrets_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
)

// appX and appY are canonical app IDs, as ulid.Make().String() mints them.
const (
	appX = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	appY = "01JZZZZZZZZZZZZZZZZZZZZZZ1"
)

// TC-761-01: AppSecret refuses traversal, malformed and non-canonical app IDs
// and non-DNS names with ErrInvalidRef and the zero Ref; a canonical ULID and
// a DNS label give exactly apps/<ULID>/<name>.
func TestAppSecret(t *testing.T) {
	badIDs := []string{
		"",
		strings.Repeat("A", 25),
		strings.Repeat("A", 27),
		"01JABCDEFGHJKMNPQRSTVWXYZI",
		"01JABCDEFGHJKMNPQRSTVWXYZL",
		"01JABCDEFGHJKMNPQRSTVWXYZO",
		"01JABCDEFGHJKMNPQRSTVWXYZU",
		"../x",
		strings.ToLower(appX),
	}
	for _, id := range badIDs {
		r, err := secrets.AppSecret(id, "db-pass")
		if !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
			t.Errorf("AppSecret(%q, db-pass) = %q, %v; want the zero Ref and ErrInvalidRef", id, r, err)
		}
	}
	badNames := []string{"", "..", "a/b", "%2e%2e", "A", "a_b", "-a", "a-", strings.Repeat("a", 64)}
	for _, name := range badNames {
		r, err := secrets.AppSecret(appX, name)
		if !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
			t.Errorf("AppSecret(appX, %q) = %q, %v; want the zero Ref and ErrInvalidRef", name, r, err)
		}
	}
	r, err := secrets.AppSecret(appX, "db-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := r.String(), "apps/"+appX+"/db-pass"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if (secrets.Ref{}).String() != "" {
		t.Error("the zero Ref renders a path")
	}
}

// TC-761-02: DeviceSecret refuses anything but two DNS-1123 labels, and
// DeviceSecret("bmc", "node-1") is devices/bmc/node-1.
func TestDeviceSecret(t *testing.T) {
	bad := []string{"", "..", "a/b", "Bmc", "a_b", "-a", "a-", strings.Repeat("a", 64)}
	for _, b := range bad {
		for _, args := range [][2]string{{b, "node-1"}, {"bmc", b}} {
			r, err := secrets.DeviceSecret(args[0], args[1])
			if !errors.Is(err, secrets.ErrInvalidRef) || r != (secrets.Ref{}) {
				t.Errorf("DeviceSecret(%q, %q) = %q, %v; want the zero Ref and ErrInvalidRef", args[0], args[1], r, err)
			}
		}
	}
	r, err := secrets.DeviceSecret("bmc", "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.String(); got != "devices/bmc/node-1" {
		t.Errorf("String() = %q, want devices/bmc/node-1", got)
	}
}
