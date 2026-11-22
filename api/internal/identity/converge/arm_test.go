package converge

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"slices"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const armedPath = "/var/lib/rasputin/identity/armed"

// armRig is an Armer over a fakeKC, memSettings and a marker file in memory.
type armRig struct {
	kc       *fakeKC
	settings *memSettings
	exists   bool
	statErr  error
	log      []string // CreateArmed and Set calls, in order
	a        *Armer
	rec      *logkittest.Recorder
}

type fakeInfo struct{ fs.FileInfo }

func newArmRig(t *testing.T) *armRig {
	t.Helper()
	r := &armRig{kc: newFakeKC(), settings: &memSettings{m: map[string]string{}}}
	log, rec := logkittest.New()
	r.rec = rec
	settings := &loggedSettings{memSettings: r.settings, log: &r.log}
	a, err := NewArmer(ArmDeps{
		Admin: r.kc, Settings: settings, Realm: testRealm, Path: armedPath,
		CreateArmed: func(path string, data []byte) error {
			r.log = append(r.log, "create "+path+" "+string(data))
			if r.exists {
				return fs.ErrExist
			}
			r.exists = true
			return nil
		},
		Stat: func(string) (fs.FileInfo, error) {
			if r.statErr != nil {
				return nil, r.statErr
			}
			if !r.exists {
				return nil, fs.ErrNotExist
			}
			return fakeInfo{}, nil
		},
		Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.a = a
	return r
}

// loggedSettings logs each Set.
type loggedSettings struct {
	*memSettings
	log *[]string
}

func (s *loggedSettings) Set(ctx context.Context, k, v string) error {
	*s.log = append(*s.log, "set "+k+"="+v)
	return s.memSettings.Set(ctx, k, v)
}

// TC-981-13: identity.arm records the realm id and the armed marker, and
// refuses a different recorded id with nothing written.
func TestArmer(t *testing.T) {
	const realmID = "realm-uuid-1"
	t.Run("unarmed with no recorded id", func(t *testing.T) {
		r := newArmRig(t)
		if err := r.a.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if want := []string{"create " + armedPath + " " + realmID + "\n", "set " + RealmIDKey + "=" + realmID}; !slices.Equal(r.log, want) {
			t.Errorf("calls = %q, want %q", r.log, want)
		}
	})
	t.Run("armed already exists", func(t *testing.T) {
		r := newArmRig(t)
		r.exists = true
		if err := r.a.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if r.settings.m[RealmIDKey] != realmID {
			t.Errorf("realm id = %q, want it set", r.settings.m[RealmIDKey])
		}
	})
	t.Run("the same recorded id with armed absent", func(t *testing.T) {
		r := newArmRig(t)
		r.settings.m[RealmIDKey] = realmID
		if err := r.a.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if want := []string{"create " + armedPath + " " + realmID + "\n"}; !slices.Equal(r.log, want) {
			t.Errorf("calls = %q, want only the file", r.log)
		}
	})
	t.Run("a different recorded id", func(t *testing.T) {
		r := newArmRig(t)
		r.settings.m[RealmIDKey] = "another-realm"
		if err := r.a.Run(t.Context()); !errors.Is(err, errArmOther) {
			t.Fatalf("Run = %v, want errArmOther", err)
		}
		if len(r.log) != 0 || r.exists || r.settings.m[RealmIDKey] != "another-realm" {
			t.Errorf("calls %q, armed %t, id %q; want nothing written", r.log, r.exists, r.settings.m[RealmIDKey])
		}
		if n := len(r.rec.AtLevel(slog.LevelError)); n != 1 {
			t.Errorf("%d ERRORs, want 1", n)
		}
	})
	t.Run("a failed realm read", func(t *testing.T) {
		r := newArmRig(t)
		r.kc.fail["GET "+realmPath] = &idclient.Error{Op: "admin", Kind: idclient.ErrUnreachable}
		if err := r.a.Run(t.Context()); !errors.Is(err, errArmRead) {
			t.Fatalf("Run = %v, want errArmRead", err)
		}
		if len(r.log) != 0 {
			t.Errorf("calls = %q, want nothing written", r.log)
		}
	})
	t.Run("Pending", func(t *testing.T) {
		r := newArmRig(t)
		for _, c := range []struct {
			id      string
			exists  bool
			statErr error
			want    bool
			err     bool
		}{
			{"", false, nil, true, false},
			{"", true, nil, true, false},
			{realmID, false, nil, true, false},
			{realmID, true, nil, false, false},
			{realmID, true, fs.ErrPermission, false, true},
		} {
			r.settings.m[RealmIDKey], r.exists, r.statErr = c.id, c.exists, c.statErr
			got, err := r.a.Pending(t.Context())
			if got != c.want || (err != nil) != c.err {
				t.Errorf("id %q exists %t statErr %v: Pending = %v, %v", c.id, c.exists, c.statErr, got, err)
			}
		}
		r.settings.getErr = errors.New("db")
		if _, err := r.a.Pending(t.Context()); err == nil {
			t.Error("an unreadable setting read as not pending")
		}
	})
}
