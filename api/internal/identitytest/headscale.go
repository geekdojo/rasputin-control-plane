package identitytest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// headscaleEnv is the on-demand mesh coordinator.
type headscaleEnv struct {
	id    string // the container id
	name  string
	url   string
	roots *x509.CertPool
}

// Headscale starts the mesh coordinator on first call, through the product's
// own supervisor (mesh.DockerSupervisor) at the image mesh-images.json pins,
// and returns its URL and a pool holding only its CA. It returns once
// GET <url>/health answers 200 over a client trusting only that CA. Later
// calls return the same coordinator, or the first call's error.
func (e *Env) Headscale(ctx context.Context) (url string, roots *x509.CertPool, err error) {
	e.hsOnce.Do(func() { e.hsErr = e.startHeadscale(ctx) })
	if e.hsErr != nil {
		return "", nil, e.hsErr
	}
	return e.hs.url, e.hs.roots, nil
}

// HeadscaleContainer is the coordinator's container name, or "" before
// Headscale has started.
func (e *Env) HeadscaleContainer() string {
	if e.hs == nil {
		return ""
	}
	return e.hs.name
}

// startHeadscale sets e.hs as soon as the container exists, so teardown
// removes a container whose start failed.
func (e *Env) startHeadscale(ctx context.Context) error {
	cfg := e.h.cfg
	suffix, err := randomHex(cfg.Rand, 6)
	if err != nil {
		return fmt.Errorf("identitytest: container name: %w", err)
	}
	meshCA, err := tlsca.Ensure(tlsca.ControlplaneConfig(), filepath.Join(e.root, "mesh-ca"), "identitytest",
		tlsca.Deps{Now: cfg.Now, Rand: cfg.Rand, Log: cfg.Logger})
	if err != nil {
		return fmt.Errorf("identitytest: mesh CA: %w", err)
	}
	port, err := proctest.FreePort()
	if err != nil {
		return fmt.Errorf("identitytest: mesh coordinator: %w", err)
	}
	name := "rasputin-identitytest-headscale-" + suffix
	sup, err := mesh.NewDockerSupervisor(mesh.DockerSupervisorConfig{
		StateDir:      filepath.Join(e.root, "headscale"),
		ContainerName: name,
		ListenAddr:    "127.0.0.1:" + strconv.Itoa(port),
		DockerBin:     cfg.DockerBin,
		Runner:        mesh.CmdRunner(cfg.Run),
		MeshCA:        meshCA,
	})
	if err != nil {
		return fmt.Errorf("identitytest: mesh coordinator: %w", err)
	}
	startErr := sup.Start(ctx)
	// The container exists from `docker run` on, even when Start then fails,
	// so its id is recorded for teardown before the error is looked at.
	out, idErr := cfg.Run(ctx, cfg.DockerBin, "inspect", "--format", "{{.Id}}", name)
	hs := &headscaleEnv{name: name, url: sup.ServerURL(), roots: x509.NewCertPool()}
	if idErr == nil {
		hs.id = strings.TrimSpace(string(out))
		e.hs = hs
	}
	if startErr != nil {
		return fmt.Errorf("identitytest: start the mesh coordinator: %w", startErr)
	}
	if idErr != nil {
		return fmt.Errorf("identitytest: mesh coordinator container id: %w", idErr)
	}
	hs.roots.AddCert(meshCA.Cert)
	if err := e.awaitHeadscaleHealth(ctx, hs); err != nil {
		return err
	}
	e.log.Info("mesh coordinator started", "container", hs.id, "url", hs.url)
	return nil
}

// awaitHeadscaleHealth returns once GET <url>/health answers 200 over a
// client that trusts only roots. The supervisor's own wait is a TCP connect,
// and docker's port proxy accepts one before Headscale listens (the request
// then ends in EOF), so the fact waited on here is Headscale's own answer. A
// container that stops running ends the wait at once; otherwise ctx bounds
// it.
func (e *Env) awaitHeadscaleHealth(ctx context.Context, hs *headscaleEnv) error {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: hs.roots}}}
	defer client.CloseIdleConnections()
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		ok, status, err := checkHeadscaleHealth(ctx, client, hs.url)
		if ok || ctx.Err() != nil {
			return ok, status, err
		}
		out, ierr := e.h.cfg.Run(ctx, e.h.cfg.DockerBin, "inspect", "--format", "{{.State.Running}}", hs.id)
		if ierr == nil && strings.TrimSpace(string(out)) != "true" {
			return false, status, &proctest.Final{Err: fmt.Errorf("container %s is not running", hs.id)}
		}
		return false, status, err
	}, func(last string) {
		e.log.Debug("mesh coordinator not healthy yet", "container", hs.id, "health", last)
	})
	var notReady *proctest.NotReadyError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &notReady):
		return fmt.Errorf("identitytest: mesh coordinator not healthy when ctx ended (last health: %s): %w", notReady.Last, notReady.Err)
	default:
		return fmt.Errorf("identitytest: mesh coordinator: %w", err)
	}
}

// checkHeadscaleHealth asks <url>/health once: 200 is healthy.
func checkHeadscaleHealth(ctx context.Context, client *http.Client, url string) (bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/health", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode == http.StatusOK, fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(body))), nil
}
