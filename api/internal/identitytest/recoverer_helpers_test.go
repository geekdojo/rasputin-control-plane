package identitytest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/execrun"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// readRepoBaseline is the repo's identity/realm-baseline.json, the
// recovery's source as the api tarball installs it.
func readRepoBaseline() ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "..", "..", "identity", "realm-baseline.json"))
}

// recoverSecretEnv is the variable the OS's recovery launcher hands kc.sh the
// temporary secret in.
const recoverSecretEnv = "RASPUTIN_RECOVER_CLIENT_SECRET"

// envRecovery is what one Recoverer over an Env saw: the temporary secret
// its recovery command's environment carried and the command's output.
type envRecovery struct {
	mu         sync.Mutex
	secretText string
	bootOut    []byte
}

func (r *envRecovery) secret() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.secretText
}

func (r *envRecovery) output() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bootOut
}

// newEnvRecoverer is identity.recover_admin over env: envUnits for
// keycloak.service, the Env's own kc.sh bootstrap-admin against its database
// and keycloak.conf, and client as the identity API. It fails the test if an
// argument carries the secret.
func newEnvRecoverer(t *testing.T, env *Env, client *idclient.Client, readBaseline func() ([]byte, error),
	restored func(ctx context.Context, jobID string) error) (*recoveradmin.Recoverer, *envRecovery) {
	t.Helper()
	https, mgmt := env.ports.get()
	units := &envUnits{env: env, home: filepath.Join(env.root, "kc"), conf: filepath.Join(env.root, "keycloak.conf"), https: https, mgmt: mgmt}
	seen := &envRecovery{}
	rec, err := recoveradmin.New(recoveradmin.Deps{
		Identity: client, Units: units, Unit: "keycloak (identitytest)",
		// The launcher's exec mode as this Env runs it: kc.sh bootstrap-admin
		// against its own database and keycloak.conf, with the secret only in
		// the command's environment (geekdojo/geekdojo-brain#1131).
		Bootstrap: func(ctx context.Context, clientID string, sec secret.Value) error {
			secretText := string(sec.Reveal())
			args := []string{"--config-file=" + units.conf, "bootstrap-admin", "service", "--optimized", "--no-prompt",
				"--client-id", clientID, "--client-secret:env", recoverSecretEnv}
			for _, a := range args {
				if secretText != "" && strings.Contains(a, secretText) {
					t.Errorf("argument %q carries the secret", a)
				}
			}
			out, err := execrun.CombinedOutputInput(ctx, append(env.kcEnv(), recoverSecretEnv+"="+secretText), nil,
				filepath.Join(units.home, "bin", "kc.sh"), args...)
			seen.mu.Lock()
			seen.secretText, seen.bootOut = secretText, out
			seen.mu.Unlock()
			if err != nil {
				t.Logf("kc.sh bootstrap-admin output:\n%s", tail(out, 40))
			}
			return err
		},
		ReadBaseline: readBaseline,
		Rand:         env.h.cfg.Rand, Restored: restored, Log: env.log, StepTimeout: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec, seen
}
