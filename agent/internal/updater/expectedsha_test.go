package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// wellFormedSHA is a syntactically valid sha256 for tests that are exercising
// something other than the hash check and only need a command the backend will
// not refuse out of hand. It is deliberately not the digest of anything.
const wellFormedSHA = "0000000000000000000000000000000000000000000000000000000000000000"

// The check that matters: an empty ExpectedSHA256 used to mean "do not compare
// the bytes to anything", so a download command with the field omitted got the
// artifact staged with no integrity check at all. Every backend refuses it now.
func TestRequireExpectedSHA_EmptyIsRefused(t *testing.T) {
	err := requireExpectedSHA("b1", "")
	if err == nil {
		t.Fatal("an empty expected sha was accepted")
	}
	if !strings.Contains(err.Error(), "no expected sha256") {
		t.Errorf("the refusal should name the missing field, got: %v", err)
	}
}

// A value that cannot possibly equal a hex digest is refused up front rather
// than after a full transfer, and the message says which fault it is.
func TestRequireExpectedSHA_MalformedIsRefused(t *testing.T) {
	for _, bad := range []string{
		"deadbeef",          // too short
		wellFormedSHA + "0", // too long
		strings.ToUpper(wellFormedSHA[:63]) + "A", // uppercase hex never matches the computed digest
		strings.Repeat("g", 64),                   // right length, not hex
	} {
		if err := requireExpectedSHA("b1", bad); err == nil {
			t.Errorf("%q was accepted as an expected sha256", bad)
		}
	}
}

func TestRequireExpectedSHA_WellFormedIsAccepted(t *testing.T) {
	sum := sha256.Sum256([]byte("anything"))
	if err := requireExpectedSHA("b1", hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("a real sha256 was refused: %v", err)
	}
}

// Each backend must refuse BEFORE it spends the transfer, because the whole
// point of hoisting the check is that a node does not move half a gigabyte to
// discover the command had nothing to check it against.
func TestBackends_RefuseAnEmptyExpectedSHABeforeDownloading(t *testing.T) {
	body := []byte("ARTIFACT-BYTES")

	newServer := func(t *testing.T) (*httptest.Server, *atomic.Int64) {
		t.Helper()
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/sig") {
				_, _ = w.Write([]byte("not-a-real-signature"))
				return
			}
			hits.Add(1)
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return srv, &hits
	}

	t.Run("openwrt-ab", func(t *testing.T) {
		srv, hits := newServer(t)
		b, err := NewOpenWrtABBackend(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = b.Download(context.Background(), "b1", srv.URL+"/bundle", srv.URL+"/sig", "", 0, nil)
		if err == nil {
			t.Fatal("openwrt-ab staged an artifact with no expected sha")
		}
		if !strings.Contains(err.Error(), "no expected sha256") {
			t.Errorf("unexpected error: %v", err)
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("artifact fetched %d times; the refusal must precede the transfer", n)
		}
	})

	t.Run("rauc", func(t *testing.T) {
		fakeRAUC(t, "ok")
		srv, hits := newServer(t)
		b, err := NewRAUCBackend(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = b.Download(context.Background(), "b1", srv.URL+"/bundle", "", "", 0, nil)
		if err == nil {
			t.Fatal("rauc staged an artifact with no expected sha")
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("artifact fetched %d times; the refusal must precede the transfer", n)
		}
	})

	t.Run("mock", func(t *testing.T) {
		srv, hits := newServer(t)
		mb, err := NewMockBackend(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = mb.Download(context.Background(), "b1", srv.URL+"/bundle", "", "", 0, nil)
		if err == nil {
			t.Fatal("mock staged an artifact with no expected sha")
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("artifact fetched %d times; the refusal must precede the transfer", n)
		}
	})
}
