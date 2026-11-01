package secretstore_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storepolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstoretest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// auditHeaderRole stands in for self-init in TestClient_JobHeaderAudited: its
// policy grants exactly what the rasputin-os init.json request needs to list
// the job header as audited, and nothing else.
const auditHeaderRole = "test-audit-header"

// auditHeaderPath is the request that lists the job header as audited.
const auditHeaderPath = "sys/config/auditing/request-headers/x-rasputin-job-id"

// auditEntry is the part of an audit line the test reads.
type auditEntry struct {
	Type    string `json:"type"`
	Request struct {
		Path      string              `json:"path"`
		Operation string              `json:"operation"`
		Headers   map[string][]string `json:"headers"`
	} `json:"request"`
	Response struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	} `json:"response"`
}

// readAudit returns the audit entries for path (the store's request path, with
// no /v1/), in file order.
func readAudit(t *testing.T, file, path string) []auditEntry {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	var out []auditEntry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e auditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("audit line is not JSON: %v", err)
		}
		if e.Request.Path == path && e.Request.Operation == "read" {
			out = append(out, e)
		}
	}
	return out
}

// TC-802-07 and TC-802-08: the api's store client, logged in with the real
// rasputin-api policy, reads a KV entry under a job against the real pinned
// store with its file audit device on. Before the job header is listed as
// audited (a store initialised before the rasputin-os init.json change), the
// read succeeds and its audit entries carry no x-rasputin-job-id. Once a role
// holding update+sudo on exactly the header's config path lists it with hmac
// false, as self-init does, the request and response entries carry the job id
// in plain text, the value is HMAC'd, and the plain value is nowhere in the
// file (geekdojo/geekdojo-brain#802).
func TestClient_JobHeaderAudited(t *testing.T) {
	bin := os.Getenv(binEnv)
	if bin == "" {
		functest.SkipOrFail(t, switchEnv, "%s is not set, so there is no secret store binary to run", binEnv)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		functest.SkipOrFail(t, switchEnv, "%s=%s: no secret store binary there: %v", binEnv, bin, err)
		return
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), nil))
	h, err := secretstoretest.New(secretstoretest.Config{
		BinaryPath: bin, TempParent: t.TempDir(), Logger: logger, Now: time.Now, Rand: rand.Reader, Audit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	apiPolicy, err := storepolicy.Text(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	store, err := h.StartWith(t.Context(), secretstoretest.Bootstrap{
		Mount: storepolicy.Mount,
		Roles: []secretstoretest.Role{
			{Name: storepolicy.APIPolicy, Policy: storepolicy.APIPolicy, PolicyText: apiPolicy},
			{Name: auditHeaderRole, Policy: auditHeaderRole,
				PolicyText: []byte(`path "` + auditHeaderPath + `" { capabilities = ["update", "sudo"] }` + "\n")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Errorf("cleanup Close: %v", err)
		}
	})
	apiTLS, err := store.ClientTLSFor(storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(t, store.URL(), apiTLS, logger)
	token, err := store.TokenFor(t.Context(), storepolicy.APIPolicy)
	if err != nil {
		t.Fatal(err)
	}

	// readUnderJob writes a fresh plain value to apps/<name> and reads it back
	// under job id, returning the value.
	readUnderJob := func(t *testing.T, name, id string) string {
		t.Helper()
		value := "plain-" + name + "-" + strings.ToLower(rand.Text())
		p := kvPath(t, storepolicy.Mount, "apps/"+name)
		if _, err := client.Write(t.Context(), token, p, map[string]secret.Value{"password": tok(value)}, 0); err != nil {
			t.Fatalf("write: %v", err)
		}
		kv, err := client.Read(jobs.ContextWithJobID(t.Context(), id), token, p, 0)
		if err != nil {
			t.Fatalf("read under job %s: %v", id, err)
		}
		if got := string(kv.Data["password"].Reveal()); got != value {
			t.Fatalf("read back %q, want the value written", got)
		}
		return value
	}

	t.Run("TC-802-08 header not audited", func(t *testing.T) {
		readUnderJob(t, "before", "job-before-802")
		entries := readAudit(t, store.AuditPath(), storepolicy.Mount+"/data/apps/before")
		if len(entries) != 2 {
			t.Fatalf("%d audit entries for the read, want a request and a response", len(entries))
		}
		for _, e := range entries {
			if _, ok := e.Request.Headers[strings.ToLower(secretstore.JobHeader)]; ok {
				t.Errorf("%s entry carries %s %v, want no such key", e.Type, secretstore.JobHeader, e.Request.Headers)
			}
		}
	})

	t.Run("TC-802-07 header audited in plain text, value hashed", func(t *testing.T) {
		adminTLS, err := store.ClientTLSFor(auditHeaderRole)
		if err != nil {
			t.Fatal(err)
		}
		adminTok, err := store.TokenFor(t.Context(), auditHeaderRole)
		if err != nil {
			t.Fatal(err)
		}
		admin := &http.Client{Transport: &http.Transport{TLSClientConfig: adminTLS}}
		t.Cleanup(admin.CloseIdleConnections)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, store.URL()+"/v1/"+auditHeaderPath,
			strings.NewReader(`{"hmac": false}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", string(adminTok.Reveal()))
		resp, err := admin.Do(req)
		if err != nil {
			t.Fatalf("list the header as audited: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Fatalf("list the header as audited: HTTP %d", resp.StatusCode)
		}

		const id = "01JB802FUNCTIONALJOB000000"
		value := readUnderJob(t, "after", id)
		entries := readAudit(t, store.AuditPath(), storepolicy.Mount+"/data/apps/after")
		types := map[string]bool{}
		for _, e := range entries {
			types[e.Type] = true
			got := e.Request.Headers[strings.ToLower(secretstore.JobHeader)]
			if len(got) != 1 || got[0] != id {
				t.Errorf("%s entry: %s = %v, want [%s] in plain text", e.Type, secretstore.JobHeader, got, id)
			}
			if e.Type == "response" {
				pw, _ := e.Response.Data.Data["password"].(string)
				if !strings.HasPrefix(pw, "hmac-sha256:") {
					t.Errorf("response entry password = %q, want it to start hmac-sha256:", pw)
				}
			}
			t.Logf("%s entry: %s = %v", e.Type, secretstore.JobHeader, got)
		}
		if len(entries) != 2 || !types["request"] || !types["response"] {
			t.Errorf("%d audit entries %v for the read, want one request and one response", len(entries), types)
		}
		raw, err := os.ReadFile(store.AuditPath())
		if err != nil {
			t.Fatal(err)
		}
		if n := bytes.Count(raw, []byte(value)); n != 0 {
			t.Errorf("the plain value occurs %d times in the audit file, want 0", n)
		} else {
			t.Logf("the plain value occurs 0 times in the %d-byte audit file", len(raw))
		}
	})
}
