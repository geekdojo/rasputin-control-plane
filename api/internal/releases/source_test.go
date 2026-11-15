package releases

import (
	"encoding/json"
	"errors"
	"testing"
)

// TC-1011-05: MemoryFloor reads the floor off a parsed manifest. A manifest
// from before the field is "no floor"; a stated floor is returned as is; a
// manifest carrying the sign-in service with no floor, or with a negative one,
// is refused rather than read as "no floor".
func TestManifestMemoryFloor(t *testing.T) {
	const n = int64(3758096384) // 3,584 MiB
	for _, c := range []struct {
		name    string
		json    string
		want    int64
		wantErr error // nil = no error; errAny = some error that is not ErrNoMemoryFloor
	}{
		{"before the field", `{"version":"2026.11.0"}`, 0, nil},
		{"floor", `{"controlPlaneMemoryFloorBytes":3758096384}`, n, nil},
		{"floor with identity", `{"controlPlaneMemoryFloorBytes":3758096384,"identityService":true}`, n, nil},
		{"identity, no floor", `{"identityService":true}`, 0, ErrNoMemoryFloor},
		{"negative floor", `{"controlPlaneMemoryFloorBytes":-1}`, 0, errAny},
		{"identity, floor 0", `{"controlPlaneMemoryFloorBytes":0,"identityService":true}`, 0, ErrNoMemoryFloor},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m Manifest
			if err := json.Unmarshal([]byte(c.json), &m); err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := m.MemoryFloor()
			switch {
			case c.wantErr == nil && err != nil:
				t.Fatalf("MemoryFloor() error = %v, want none", err)
			case c.wantErr == ErrNoMemoryFloor && !errors.Is(err, ErrNoMemoryFloor):
				t.Fatalf("MemoryFloor() error = %v, want ErrNoMemoryFloor", err)
			case c.wantErr == errAny && (err == nil || errors.Is(err, ErrNoMemoryFloor)):
				t.Fatalf("MemoryFloor() error = %v, want a negative-floor error", err)
			}
			if got != c.want {
				t.Errorf("MemoryFloor() = %d, want %d", got, c.want)
			}
		})
	}
}

var errAny = errors.New("any error")
