package identitytest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"text/template"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// kcPaths are the files keycloak.conf names.
type kcPaths struct {
	CertFile, KeyFile string // Keycloak's server leaf
	TrustFile         string // the test CA PEM: the only issuer a client leaf may have
	VaultDir          string // the file vault the build options enable; empty
}

// kcPorts are the ports keycloak.conf names. HTTPS and Mgmt are 0 in the
// harness: the kernel assigns them and Keycloak reports what it bound, so no
// port is guessed before the JVM binds it (F-966-04).
type kcPorts struct {
	HTTPS, Mgmt, DB int
}

// renderKeycloakConf is the runtime keycloak.conf: TLS 1.3 only with the
// server leaf, the test CA as the trust store (https-client-auth=required is
// a build option), no plain HTTP, loopback only, the local cache, the front's
// URL as hostname, and the database. It is #959's keycloak.conf.tmpl with the
// harness's values. The caller clears the returned bytes, which hold the
// database password.
func renderKeycloakConf(p kcPaths, ports kcPorts, hostname string, dbPassword secret.Value) []byte {
	var b bytes.Buffer
	line := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	line("http-enabled", "false")
	line("http-host", "127.0.0.1")
	line("https-port", strconv.Itoa(ports.HTTPS))
	line("http-management-port", strconv.Itoa(ports.Mgmt))
	line("https-protocols", "TLSv1.3")
	line("https-certificate-file", p.CertFile)
	line("https-certificate-key-file", p.KeyFile)
	line("https-trust-store-file", p.TrustFile)
	line("hostname", hostname)
	line("cache", "local")
	line("vault-dir", p.VaultDir)
	line("db-url", "jdbc:postgresql://127.0.0.1:"+strconv.Itoa(ports.DB)+"/"+dbName)
	line("db-username", dbUser)
	b.WriteString("db-password=")
	b.Write(dbPassword.Reveal())
	b.WriteString("\n")
	return b.Bytes()
}

//go:embed realm.json.tmpl
var realmTemplate string

var realmTmpl = template.Must(template.New("realm").Parse(realmTemplate))

// renderRealm is the imported realm: realm harness, the public client
// harness-public with the standard flow and S256 PKCE, and one enabled user
// with a password and no required actions. The caller clears the returned
// bytes, which hold the password.
func renderRealm(user string, password secret.Value) ([]byte, error) {
	// json.Marshal of a string is a JSON string literal, quotes included, so
	// no value can break out of its field.
	quote := func(s []byte) (string, error) {
		q, err := json.Marshal(string(s))
		return string(q), err
	}
	pw, err := quote(password.Reveal())
	if err != nil {
		return nil, fmt.Errorf("identitytest: realm: %w", err)
	}
	u, err := quote([]byte(user))
	if err != nil {
		return nil, fmt.Errorf("identitytest: realm: %w", err)
	}
	var b bytes.Buffer
	if err := realmTmpl.Execute(&b, map[string]string{
		"Realm": Realm, "ClientID": ClientID, "RedirectURI": RedirectURI, "User": u, "Password": pw,
	}); err != nil {
		return nil, fmt.Errorf("identitytest: realm: %w", err)
	}
	return b.Bytes(), nil
}
