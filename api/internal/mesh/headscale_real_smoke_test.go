//go:build smoke

// Live-Headscale smoke test for RealClient. Excluded from default go test
// runs by the `smoke` build tag — invoke explicitly with:
//
//	HEADSCALE_URL=http://127.0.0.1:18080 \
//	HEADSCALE_API_KEY=hskey-api-... \
//	go test -tags=smoke -run TestSmoke -count=1 -v ./api/internal/mesh/...
//
// Bootstrap (manual, one-time per Headscale install):
//
//	headscale users create rasputin-operator
//	headscale apikeys create --expiration 1h
//
// The test exercises every RealClient method against the live server, with
// per-step pass/fail and a brief summary. It leaves a marker user
// ("smoke-only") and at least one expired pre-auth key behind — those are
// fine to clean up manually or by tearing the Headscale install down.

package mesh

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSmoke_RealClient_AgainstLiveHeadscale(t *testing.T) {
	url := os.Getenv("HEADSCALE_URL")
	key := os.Getenv("HEADSCALE_API_KEY")
	if url == "" || key == "" {
		t.Fatal("HEADSCALE_URL and HEADSCALE_API_KEY must be set")
	}

	c, err := NewRealClient(RealClientConfig{
		BaseURL:        url,
		APIKey:         key,
		RequestTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRealClient: %v", err)
	}
	if c.Backend() != "headscale" {
		t.Fatalf("Backend(): %q", c.Backend())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. EnsureUser for the pre-existing operator (list-then-skip-create path).
	t.Run("EnsureUser_existing", func(t *testing.T) {
		if err := c.EnsureUser(ctx, "rasputin-operator"); err != nil {
			t.Fatalf("EnsureUser(rasputin-operator): %v", err)
		}
		if id, ok := c.cachedUserID("rasputin-operator"); !ok || id == "" {
			t.Errorf("cache populated? id=%q ok=%v", id, ok)
		}
	})

	// 2. EnsureUser for a brand-new user (list-then-create path).
	t.Run("EnsureUser_new", func(t *testing.T) {
		// Use a name unique enough that re-runs against the same Headscale
		// don't keep re-creating; once created the next call is list-only.
		if err := c.EnsureUser(ctx, "smoke-only"); err != nil {
			t.Fatalf("EnsureUser(smoke-only): %v", err)
		}
	})

	// 3. EnsureUser idempotent re-call should hit the in-memory cache and
	// issue ZERO further HTTP calls.
	t.Run("EnsureUser_cached", func(t *testing.T) {
		if err := c.EnsureUser(ctx, "smoke-only"); err != nil {
			t.Fatalf("EnsureUser(smoke-only) repeat: %v", err)
		}
	})

	// 4. CreatePreAuthKey with explicit Expiry + tag.
	var keyID, plaintext string
	t.Run("CreatePreAuthKey", func(t *testing.T) {
		var err error
		exp := time.Now().Add(time.Hour).UTC()
		keyID, plaintext, err = c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{
			User:     "rasputin-operator",
			Reusable: false,
			Expiry:   exp,
			Tags:     []string{"tag:user-device"},
		})
		if err != nil {
			t.Fatalf("CreatePreAuthKey: %v", err)
		}
		if keyID == "" || plaintext == "" {
			t.Fatalf("empty id or plaintext: id=%q plaintext=%q", keyID, plaintext)
		}
		// New v0.28 keys start with hskey-auth-; older raw secrets are also valid.
		t.Logf("minted key id=%s plaintext=%s…", keyID, safePrefix(plaintext))
	})

	// 5. CreatePreAuthKey with omitted Expiry — RealClient must NOT send
	// a zero-time field (Headscale would treat it as already-expired).
	t.Run("CreatePreAuthKey_zeroExpiryOmitted", func(t *testing.T) {
		id, _, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{
			User:     "smoke-only",
			Reusable: true,
		})
		if err != nil {
			t.Fatalf("CreatePreAuthKey (zero expiry): %v", err)
		}
		// Verify Headscale stored a non-past expiration.
		all, err := c.ListPreAuthKeys(ctx, "smoke-only")
		if err != nil {
			t.Fatalf("ListPreAuthKeys(smoke-only): %v", err)
		}
		var found *HSPreAuthKey
		for i := range all {
			if all[i].ID == id {
				found = &all[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("created key id=%s missing from list", id)
		}
		if !found.Expiration.IsZero() && !found.Expiration.After(time.Now().UTC()) {
			t.Errorf("zero-expiry key was registered as already-expired: %v", found.Expiration)
		}
	})

	// 6. ListPreAuthKeys without filter returns everything.
	t.Run("ListPreAuthKeys_all", func(t *testing.T) {
		all, err := c.ListPreAuthKeys(ctx, "")
		if err != nil {
			t.Fatalf("ListPreAuthKeys(all): %v", err)
		}
		if len(all) < 2 {
			t.Errorf("expected >=2 keys after smoke setup, got %d", len(all))
		}
	})

	// 7. ListPreAuthKeys with user filter strictly returns that user's keys
	// and strips plaintext (Headscale-side behavior).
	t.Run("ListPreAuthKeys_filtered", func(t *testing.T) {
		opOnly, err := c.ListPreAuthKeys(ctx, "rasputin-operator")
		if err != nil {
			t.Fatalf("ListPreAuthKeys(rasputin-operator): %v", err)
		}
		for _, k := range opOnly {
			if k.User != "rasputin-operator" {
				t.Errorf("filter leak: user=%q in rasputin-operator slice", k.User)
			}
			if k.Plaintext != "" {
				t.Errorf("list returned plaintext (real Headscale should strip): %q", k.Plaintext)
			}
		}
	})

	// 8. ExpirePreAuthKey moves the expiration into the past; verify via list.
	t.Run("ExpirePreAuthKey", func(t *testing.T) {
		if err := c.ExpirePreAuthKey(ctx, keyID); err != nil {
			t.Fatalf("ExpirePreAuthKey(%s): %v", keyID, err)
		}
		all, err := c.ListPreAuthKeys(ctx, "")
		if err != nil {
			t.Fatalf("ListPreAuthKeys (post-expire): %v", err)
		}
		var found *HSPreAuthKey
		for i := range all {
			if all[i].ID == keyID {
				found = &all[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("expired key %s missing from list", keyID)
		}
		if found.Expiration.After(time.Now().UTC()) {
			t.Errorf("key %s still has future expiration: %v", keyID, found.Expiration)
		}
	})

	// 9. ListNodes — no Tailscale clients joined; expect [] (or whatever
	// the live tailnet currently has). We just assert the call returns.
	t.Run("ListNodes", func(t *testing.T) {
		nodes, err := c.ListNodes(ctx)
		if err != nil {
			t.Fatalf("ListNodes: %v", err)
		}
		t.Logf("nodes registered: %d", len(nodes))
	})

	// 10. SetNodeRoutes against a missing node id should surface an
	// HTTPError mentioning the node id. Real Headscale v0.28 returns
	// HTTP 400 with gRPC code 3 (InvalidArgument) for "node no longer
	// exists" — NOT 404 the way grpc-gateway docs suggest — so the
	// assertion checks the substring rather than the status code. We
	// don't have a real node to approve routes against (no `tailscale up`
	// was run); error-path validation is the load-bearing piece.
	t.Run("SetNodeRoutes_missing", func(t *testing.T) {
		err := c.SetNodeRoutes(ctx, "99999", []string{"10.0.0.0/24"})
		if err == nil {
			t.Fatal("expected error for missing node id, got nil")
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "99999") || !strings.Contains(msg, "exist") {
			t.Errorf("expected err to mention node id and 'exist', got %v", err)
		}
		t.Logf("got expected error: %v", err)
	})
}

func safePrefix(s string) string {
	if len(s) > 20 {
		return s[:20]
	}
	return s
}
