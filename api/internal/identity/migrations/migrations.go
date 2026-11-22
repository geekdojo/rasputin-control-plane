// Package migrations is the identity realm's append-only migrations and the
// runner that applies them one recorded step at a time
// (geekdojo/geekdojo-brain#981, Identity 3.5; platform.md §4.2).
//
// The realm baseline (identity/realm-baseline.json) is what a fresh install
// imports. Once the baseline is armed (realm-baseline.lock's armed-at names a
// release), it is frozen, and a realm change ships as a new migration here:
// one file mNNNN_<name>.go holding one Migration, appended to All and locked
// by its sha256 in migrations.lock. A shipped migration is never edited;
// TestLock fails CI when one is.
//
// The realm records how far it has come in its attribute rasputin.migrations,
// so a cluster upgraded across several releases applies each migration it
// lacks, in order, once.
package migrations

import (
	"context"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// Admin is the api's Admin API session as rasputin-admin (*idclient.Session).
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Migration is one realm change.
//
// Apply must be idempotent: a run that fails after Apply and before the
// record is written applies it again. It must not write a field converge
// owns (converge's desired state), because converge puts those back and the
// two would then disagree about the realm. It writes the realm through a,
// for the realm named realm.
type Migration struct {
	ID    int
	Name  string
	Apply func(ctx context.Context, a Admin, realm string) error
}

// All is the shipped migrations, in order, IDs 1..n. It is empty while the
// baseline is unarmed (armed-at=none): until then a realm change goes into
// the baseline itself.
var All = []Migration{}
