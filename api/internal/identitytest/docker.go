package identitytest

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
)

// docker is the five docker calls the harness makes, over the injected
// runner.
type docker struct {
	bin string
	run CmdRunner
}

// runDetached is `docker run -d <args>`; it returns the container id.
func (d docker) runDetached(ctx context.Context, args ...string) (string, error) {
	out, err := d.run(ctx, d.bin, append([]string{"run", "-d"}, args...)...)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if i := strings.LastIndexByte(id, '\n'); i >= 0 {
		id = strings.TrimSpace(id[i+1:]) // a pull's progress lines come first
	}
	if id == "" {
		return "", errors.New("docker run printed no container id")
	}
	return id, nil
}

// loopbackPort is the host port `docker port <id> <port>` maps on
// 127.0.0.1.
func (d docker) loopbackPort(ctx context.Context, id, port string) (int, error) {
	out, err := d.run(ctx, d.bin, "port", id, port)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		host, p, err := net.SplitHostPort(strings.TrimSpace(line))
		if err == nil && host == "127.0.0.1" {
			return strconv.Atoi(p)
		}
	}
	return 0, fmt.Errorf("docker port %s %s maps nothing on 127.0.0.1: %q", id, port, strings.TrimSpace(string(out)))
}

// exec is `docker exec <id> <args>`.
func (d docker) exec(ctx context.Context, id string, args ...string) ([]byte, error) {
	return d.run(ctx, d.bin, append([]string{"exec", id}, args...)...)
}

// rm is `docker rm -f -v <id>`: the container and its anonymous volumes.
func (d docker) rm(ctx context.Context, id string) error {
	_, err := d.run(ctx, d.bin, "rm", "-f", "-v", id)
	return err
}

// listed reports whether `docker ps -aq --filter id=<id>` still lists it.
func (d docker) listed(ctx context.Context, id string) (bool, error) {
	out, err := d.run(ctx, d.bin, "ps", "-aq", "--filter", "id="+id)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// info is `docker info`, which fails when the daemon is unreachable.
func (d docker) info(ctx context.Context) error {
	_, err := d.run(ctx, d.bin, "info", "--format", "{{.ServerVersion}}")
	return err
}

// startPostgres runs the pinned PostgreSQL with its data on a tmpfs (in its
// anonymous volume, on a fixed port, under Config.pgRestartable), the
// password passed by --env-file so it never appears in an argument or in
// docker's output, and returns its loopback port once pg_isready answers.
func (e *Env) startPostgres(ctx context.Context) (int, error) {
	suffix, err := randomHex(e.h.cfg.Rand, 6)
	if err != nil {
		return 0, fmt.Errorf("identitytest: container name: %w", err)
	}
	envFile := filepath.Join(e.root, "pg.env")
	env := []byte("POSTGRES_USER=" + dbUser + "\nPOSTGRES_DB=" + dbName + "\nPOSTGRES_PASSWORD=")
	env = append(env, e.dbPassword.Reveal()...)
	env = append(env, '\n')
	err = atrest.WriteSecretFile(envFile, env)
	clear(env)
	if err != nil {
		return 0, fmt.Errorf("identitytest: database env file: %w", err)
	}
	args := []string{"--name", "rasputin-identitytest-pg-" + suffix, "-p", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql"}
	if e.h.cfg.pgRestartable {
		fixed, err := proctest.FreePort()
		if err != nil {
			return 0, fmt.Errorf("identitytest: identity database port: %w", err)
		}
		args = []string{"--name", "rasputin-identitytest-pg-" + suffix, "-p", "127.0.0.1:" + strconv.Itoa(fixed) + ":5432"}
	}
	id, err := e.docker.runDetached(ctx, append(args, "--env-file", envFile, PostgresImage)...)
	if err != nil {
		return 0, fmt.Errorf("identitytest: start the identity database: %w", err)
	}
	e.pgID = id
	port, err := e.docker.loopbackPort(ctx, id, "5432/tcp")
	if err != nil {
		return 0, fmt.Errorf("identitytest: identity database port: %w", err)
	}
	if err := e.docker.awaitPostgres(ctx, e.log, id, "-h", "127.0.0.1", "-U", dbUser, "-d", dbName); err != nil {
		return 0, fmt.Errorf("identitytest: identity database: %w", err)
	}
	e.log.Info("identity database started", "container", id, "addr", "127.0.0.1:"+strconv.Itoa(port), "image", PostgresImage)
	return port, nil
}

// awaitPostgres returns nil once `pg_isready <isready>` inside container id
// answers ready. A container that is not running fails at once, since it
// will never be ready; otherwise the wait ends only with ctx, and the error
// names the last pg_isready status. Each new status is logged at DEBUG.
func (d docker) awaitPostgres(ctx context.Context, log *slog.Logger, id string, isready ...string) error {
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		out, err := d.exec(ctx, id, append([]string{"pg_isready"}, isready...)...)
		status := strings.TrimSpace(string(out))
		if err != nil && strings.Contains(status, "is not running") {
			return false, status, &proctest.Final{Err: fmt.Errorf("container %s is not running: %s", id, status)}
		}
		return err == nil, status, nil
	}, func(last string) {
		log.Debug("identity database not ready yet", "container", id, "pg_isready", last)
	})
	var notReady *proctest.NotReadyError
	if errors.As(err, &notReady) {
		return fmt.Errorf("container %s not ready when ctx ended (last pg_isready: %s): %w", id, notReady.Last, notReady.Err)
	}
	return err
}

// randomHex is n random bytes as hex.
func randomHex(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomToken is n random bytes as unpadded base64url.
func randomToken(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	defer clear(b)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
