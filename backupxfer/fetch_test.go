package backupxfer_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
)

// The restore client against a stand-in for the api's restore-stream
// endpoint: the credential travels as a bearer, a refusal comes back with
// its code, a body that is not a volume tar is refused, and the credential
// never appears in an error.

const restoreCred = "rbx1.RESTORE-CREDENTIAL-STAND-IN.sig"

func egressServer(t *testing.T, body string, handler func(w http.ResponseWriter, r *http.Request) bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+backupxfer.EgressPathPrefix, func(w http.ResponseWriter, r *http.Request) {
		if handler != nil && !handler(w, r) {
			return
		}
		w.Header().Set("Content-Type", backupxfer.EgressContentType)
		w.Header().Set(backupxfer.HeaderPlaintextDigest, "ABCDEF")
		w.Header().Set(backupxfer.HeaderPlaintextBytes, strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchStreamsAMemberOnItsCredential(t *testing.T) {
	var seenAuth, seenPath string
	srv := egressServer(t, "TAR-BYTES", func(w http.ResponseWriter, r *http.Request) bool {
		seenAuth, seenPath = r.Header.Get("Authorization"), r.URL.Path
		return true
	})
	source, err := backupxfer.EgressDestination(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	f, err := backupxfer.FetcherFor(source, backupxfer.HTTPOptions{AcceptWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Get(context.Background(), backupxfer.GetRequest{Source: source, Generation: genID, Member: memVW, Credential: restoreCred})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = st.Body.Close() }()
	got, _ := io.ReadAll(st.Body)
	if string(got) != "TAR-BYTES" || st.DeclaredDigest != "abcdef" || st.DeclaredBytes != 9 {
		t.Fatalf("stream = %q %+v", got, st)
	}
	if seenAuth != "Bearer "+restoreCred {
		t.Fatalf("authorization header %q", seenAuth)
	}
	if seenPath != backupxfer.EgressPathPrefix+genID+"/"+memVW {
		t.Fatalf("path %q", seenPath)
	}
	if gen, mem, ok := backupxfer.SplitEgressPath(seenPath); !ok || gen != genID || mem != memVW {
		t.Fatalf("SplitEgressPath(%q) = %q %q %v", seenPath, gen, mem, ok)
	}
}

func TestFetchCarriesTheSourcesRefusalCode(t *testing.T) {
	srv := egressServer(t, "", func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"code":"no-restore","detail":"no restore has that generation open"}`)
		return false
	})
	source, _ := backupxfer.EgressDestination(srv.URL)
	f, _ := backupxfer.FetcherFor(source, backupxfer.HTTPOptions{})
	_, err := f.Get(context.Background(), backupxfer.GetRequest{Source: source, Generation: genID, Member: memVW, Credential: restoreCred})
	var refused *backupxfer.RefusedError
	if !errors.As(err, &refused) || refused.Problem.Code != backupxfer.CodeNoRestore || refused.Status != http.StatusConflict {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), restoreCred) {
		t.Fatal("the credential is in the error")
	}
}

func TestFetchRefusesABodyThatIsNotAVolumeTar(t *testing.T) {
	srv := egressServer(t, "", func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<html>a captive portal</html>")
		return false
	})
	source, _ := backupxfer.EgressDestination(srv.URL)
	f, _ := backupxfer.FetcherFor(source, backupxfer.HTTPOptions{})
	_, err := f.Get(context.Background(), backupxfer.GetRequest{Source: source, Generation: genID, Member: memVW, Credential: restoreCred})
	var refused *backupxfer.RefusedError
	if !errors.As(err, &refused) || refused.Problem.Code != backupxfer.CodeNotAnArchive {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchRefusesByShapeBeforeDialling(t *testing.T) {
	f, _ := backupxfer.FetcherFor("https://cp.test"+backupxfer.EgressPathPrefix, backupxfer.HTTPOptions{})
	if _, err := f.Get(context.Background(), backupxfer.GetRequest{Source: "https://cp.test/api/backup/egress/", Generation: "../x", Member: memVW, Credential: "c"}); err == nil {
		t.Fatal("a generation id of the wrong shape was accepted")
	}
	if _, err := f.Get(context.Background(), backupxfer.GetRequest{Source: "https://cp.test/api/backup/egress/", Generation: genID, Member: memVW}); err == nil {
		t.Fatal("a fetch with no credential was accepted")
	}
	if _, err := backupxfer.FetcherFor("s3://bucket/prefix", backupxfer.HTTPOptions{}); !errors.Is(err, backupxfer.ErrUnsupportedDestination) {
		t.Fatalf("s3: %v", err)
	}
	if _, err := backupxfer.EgressDestination("not a url"); err == nil {
		t.Fatal("a bare word is not a base URL")
	}
}
