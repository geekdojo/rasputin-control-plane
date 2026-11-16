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
)

// readRepoBaseline is the repo's identity/realm-baseline.json, the
// recovery's source as the api tarball installs it.
func readRepoBaseline() ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "..", "..", "identity", "realm-baseline.json"))
}

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
		Bootstrap: func(ctx context.Context, args, extra []string) error {
			var secretText string
			for _, e := range extra {
				if v, ok := strings.CutPrefix(e, recoveradmin.SecretEnv+"="); ok {
					secretText = v
				}
			}
			for _, a := range args {
				if secretText != "" && strings.Contains(a, secretText) {
					t.Errorf("argument %q carries the secret", a)
				}
			}
			out, err := execrun.CombinedOutputEnv(ctx, append(env.kcEnv(), extra...),
				filepath.Join(units.home, "bin", "kc.sh"), append([]string{"--config-file=" + units.conf}, args...)...)
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
