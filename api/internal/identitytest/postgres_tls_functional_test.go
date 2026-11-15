package identitytest

// TestPostgresTLSOnly proves capability rows T69 and T70 against the real
// pinned PostgreSQL (PostgresImage): a TLS-only hostssl configuration refuses
// a connection without TLS and admits the same one over TLS with a client
// certificate, and the server accepts its key from a file shaped the way
// LoadCredential= delivers it (geekdojo/geekdojo-brain#972). It needs only
// docker, not Keycloak, so it starts its own container rather than the
// package's Env. It skips without RASPUTIN_IDENTITY_HOME or docker, and fails
// instead under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job
// sets it.

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// credDir is where LoadCredential= puts keycloak-db.service's files, and
// where testdata/postgres-tls-only/start.sh puts them in its stead.
const credDir = "/run/credentials/keycloak-db.service"

// logs is the last n lines of `docker logs <id>`, stdout and stderr.
func (d docker) logs(ctx context.Context, id, n string) string {
	out, err := d.run(ctx, d.bin, "logs", "--tail", n, id)
	if err != nil {
		return "docker logs failed: " + err.Error() + ": " + string(out)
	}
	return string(out)
}

func TestPostgresTLSOnly(t *testing.T) {
	p := NewPackage(ConfigFromEnv)
	cfg, err := p.loadConfig()
	if err != nil {
		functest.SkipOrFail(t, SwitchEnv, "%v", err) // TC-972-16
		return
	}
	if !p.preflightDocker(t, cfg, "TestPostgresTLSOnly's PostgreSQL") { // TC-972-16
		return
	}
	ctx := t.Context()
	d := docker{bin: cfg.DockerBin, run: cfg.Run}

	// The test CA, a server leaf whose only SAN is 127.0.0.1, and a client
	// leaf whose CN is the role the hba line admits by certificate.
	root := t.TempDir()
	ca, err := tlsca.Ensure(caConfig(), filepath.Join(root, "ca"), "identitytest",
		tlsca.Deps{Now: cfg.Now, Rand: cfg.Rand, Log: cfg.Logger})
	if err != nil {
		t.Fatalf("test CA: %v", err)
	}
	server, err := ca.MintLeafToDisk(filepath.Join(root, "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "identitytest postgres", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("server leaf: %v", err)
	}
	client, err := ca.MintLeafToDisk(filepath.Join(root, "client"), tlsca.LeafSpec{
		Usage: tlsca.UsageClient, CommonName: dbUser,
	})
	if err != nil {
		t.Fatalf("client leaf: %v", err)
	}
	conf, err := filepath.Abs(filepath.Join("testdata", "postgres-tls-only"))
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := randomHex(cfg.Rand, 6)
	if err != nil {
		t.Fatalf("container name: %v", err)
	}

	id, err := d.runDetached(ctx, "--name", "rasputin-identitytest-pgtls-"+suffix,
		"--network", "none", "--tmpfs", "/var/lib/postgresql",
		"-v", filepath.Dir(server.CertPath)+":/src/server:ro",
		"-v", filepath.Join(root, "ca", caCertFile)+":/src/ca.pem:ro",
		"-v", filepath.Dir(client.CertPath)+":/client:ro",
		"-v", conf+":/etc/rasputin/identity:ro",
		"--entrypoint", "sh", PostgresImage, "/etc/rasputin/identity/start.sh")
	if err != nil {
		t.Fatalf("start the TLS-only database: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background() // t.Context() has ended by now
		if err := d.rm(ctx, id); err != nil {
			t.Errorf("remove container %s: %v", id, err)
			return
		}
		switch listed, err := d.listed(ctx, id); {
		case err != nil:
			t.Errorf("cannot show container %s is gone: %v", id, err)
		case listed:
			t.Errorf("container %s is still listed after its removal", id)
		}
	})
	if err := d.awaitPostgres(ctx, cfg.Logger, id, "-h", "127.0.0.1", "-U", dbUser, "-d", dbName); err != nil {
		t.Fatalf("the TLS-only database never became ready: %v\nlast 20 lines of docker logs %s:\n%s", err, id, d.logs(ctx, id, "20"))
	}
	cfg.Logger.Info("tls-only database started", "container", id, "image", PostgresImage)

	psql := func(conninfo, sql string) (string, error) {
		out, err := d.exec(ctx, id, "psql", conninfo, "-X", "-A", "-t", "-c", sql)
		return strings.TrimSpace(string(out)), err
	}
	const target = "host=127.0.0.1 user=" + dbUser + " dbname=" + dbName
	const verified = target + " sslmode=verify-full sslrootcert=/src/ca.pem sslcert=/client/leaf.pem sslkey=/client/leaf.key"

	// T69: the refusal, and its control.
	t.Run("refuses_a_connection_without_TLS", func(t *testing.T) {
		// TC-972-13
		const want = `no pg_hba.conf entry for host "127.0.0.1", user "keycloak", database "keycloak", no encryption`
		out, err := psql(target+" sslmode=disable", "SELECT 1")
		if err == nil || !strings.Contains(out, want) {
			t.Errorf("psql with sslmode=disable: err=%v, output %q; want a non-zero exit with %q", err, out, want)
		}
		// TC-972-14: the same host, user and database over TLS with a
		// certificate are admitted, so the refusal is the missing TLS alone.
		out, err = psql(verified, "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
		if err != nil || out != "t|TLSv1.3" {
			t.Errorf("psql over verify-full with a client certificate: err=%v, output %q; want exit 0 and %q", err, out, "t|TLSv1.3")
		}
		t.Logf("control over TLS: %s", out)
	})

	// T70: the K-P3 cell, PostgreSQL accepting the credential key file.
	t.Run("accepts_its_key_from_a_credential_file", func(t *testing.T) {
		// TC-972-15: the shape under test, as LoadCredential= gives it.
		paths := []string{credDir, credDir + "/server.pem", credDir + "/server.key", credDir + "/identity-ca.pem"}
		out, err := d.exec(ctx, id, append([]string{"stat", "-c", "%a %U:%G"}, paths...)...)
		if err != nil {
			t.Fatalf("stat the credential files: %v: %s", err, out)
		}
		got := strings.Split(strings.TrimSpace(string(out)), "\n")
		want := []string{"500 postgres:postgres", "400 postgres:postgres", "400 postgres:postgres", "400 postgres:postgres"}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("stat -c '%%a %%U:%%G' %v = %q, want %q", paths, got, want)
		}
		t.Logf("credential files: %q", got)
		// verify-full against the test CA succeeds only if the server
		// presents the leaf whose key sits in credDir.
		ssl, err := psql(verified, "SHOW ssl")
		if err != nil || ssl != "on" {
			t.Errorf("SHOW ssl over verify-full: err=%v, output %q; want exit 0 and %q", err, ssl, "on")
		}
		t.Logf("SHOW ssl: %s", ssl)
	})
}
