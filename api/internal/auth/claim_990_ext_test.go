package auth_test

import (
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-990-08: two concurrent callbacks in first run, each claiming the same
// account, over one real SQLite file and the real accounts.Designations:
// exactly one first_admin row and one designation, both sessions stored,
// and exactly one call reports claimed. 100 iterations, each on a fresh
// database.
func TestCreateWithClaim_TC990_08_Concurrent(t *testing.T) {
	for i := range 100 {
		path := filepath.Join(t.TempDir(), "rasputin.db")
		store, err := auth.OpenStore(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		des, err := accounts.OpenDesignations(t.Context(), path, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		sessions, err := auth.NewConsoleSessions(store, time.Now, rand.Reader, des)
		if err != nil {
			t.Fatal(err)
		}
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			claimed int
			cookies []secret.Value
		)
		for j := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p := auth.Principal{Sub: []string{"sub-a", "sub-b"}[j], Session: auth.SessionRef{SID: []string{"sid-a", "sid-b"}[j]}}
				c, ok, err := sessions.CreateWithClaim(t.Context(), p, &auth.Claim{Sub: "sub-a"})
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					t.Errorf("iteration %d: %v", i, err)
					return
				}
				cookies = append(cookies, c)
				if ok {
					claimed++
				}
			}()
		}
		wg.Wait()
		if claimed != 1 {
			t.Fatalf("iteration %d: %d calls claimed, want 1", i, claimed)
		}
		ds, err := des.List(t.Context())
		if err != nil || len(ds) != 1 || ds[0].Sub != "sub-a" || ds[0].Reason != accounts.ReasonFirstAdmin ||
			ds[0].ConsoleRole != "admin" || ds[0].AppRole != accounts.AppAdmin {
			t.Fatalf("iteration %d: designations %+v, %v", i, ds, err)
		}
		if first, err := store.FirstRun(t.Context()); first || err != nil {
			t.Fatalf("iteration %d: first run %v after the claim (%v)", i, first, err)
		}
		for _, c := range cookies {
			if _, ok, err := sessions.Resolve(t.Context(), c); !ok || err != nil {
				t.Fatalf("iteration %d: a session was not stored (%v)", i, err)
			}
			c.Destroy()
		}
		_ = des.Close()
		_ = store.Close()
	}
}
