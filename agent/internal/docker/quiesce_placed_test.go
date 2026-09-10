package docker

import (
	"errors"
	"strings"
	"testing"
)

// TestParseVolumeInspect_RefusesAPlacedVolume pins the fail-closed rule that
// keeps a §6.4-placed volume out of the §4 backup path.
//
// Why a refusal rather than a fix: docker reports a bind-form local volume's
// Mountpoint as the usual /var/lib/docker/volumes/<name>/_data and keeps the
// real path in Options.device. The device is only mounted over _data WHILE A
// CONTAINER HOLDS IT, and §4.3's default quiesce is `stop` — so a backup that
// trusted Mountpoint would copy an empty directory and report SUCCESS. An
// empty archive that claims to have worked is precisely the outcome §4.4
// exists to prevent.
func TestParseVolumeInspect_RefusesAPlacedVolume(t *testing.T) {
	const mp = "/var/lib/rasputin/docker/volumes/rasp_a1_data/_data"
	const device = "/var/lib/rasputin/data/0e7bd9d9-4083-48f2-858b-5986495536a7/apps/a1/data"

	for _, tc := range []struct {
		name       string
		out        string
		wantRefuse bool
		wantPath   string
	}{
		{
			name:     "an ordinary named volume resolves as it always did",
			out:      mp + "\t\n",
			wantPath: mp,
		},
		{
			// docker's --format prints this literal when the key is absent on
			// some versions; it must not be read as a real device path.
			name:     "the <no value> placeholder is not a device",
			out:      mp + "\t<no value>\n",
			wantPath: mp,
		},
		{
			// A daemon that emits no tab at all — the format string is ours, so
			// this is the shape an older docker or a changed builder produces.
			name:     "no device field at all still resolves",
			out:      mp + "\n",
			wantPath: mp,
		},
		{
			name:       "a volume bound onto a data disk is refused",
			out:        mp + "\t" + device + "\n",
			wantRefuse: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseVolumeInspect("rasp_a1_data", []byte(tc.out))

			if tc.wantRefuse {
				if !errors.Is(err, ErrPlacedVolumeUnsupported) {
					t.Fatalf("parseVolumeInspect = %q, %v; want ErrPlacedVolumeUnsupported", got, err)
				}
				// The refusal has to name the device, or an operator reading the
				// job feed cannot tell which disk is involved.
				if !strings.Contains(err.Error(), device) {
					t.Errorf("refusal does not name the bind device %q: %v", device, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseVolumeInspect: unexpected error: %v", err)
			}
			if got != tc.wantPath {
				t.Errorf("parseVolumeInspect = %q; want %q", got, tc.wantPath)
			}
		})
	}
}
