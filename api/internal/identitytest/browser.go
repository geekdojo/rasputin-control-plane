package identitytest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

// browserEnv is the on-demand browser: one Chrome under the Env's context.
type browserEnv struct {
	allocCancel   context.CancelFunc
	browserCtx    context.Context
	browserCancel context.CancelFunc

	mu  sync.Mutex
	cmd *exec.Cmd // set by the allocator just before Chrome starts
}

// Browser starts the pinned Chrome on first call and returns a chromedp
// context for it and its cancel. Chrome runs headless with a profile under
// the root, in a process group of its own, with its crash reporter off, and
// trusts exactly one certificate beyond the system's: the front's leaf, by
// its SPKI hash. It refuses a Chrome that is not the pinned release. Later
// calls return the same browser, or the first call's error. Close stops
// Chrome and its helpers.
//
// --no-sandbox: the Chrome for Testing build is not under an AppArmor profile
// and the CI runner restricts unprivileged user namespaces, so the sandbox
// cannot start there; the browser loads only the harness's own pages.
func (e *Env) Browser(ctx context.Context) (context.Context, context.CancelFunc, error) {
	e.brOnce.Do(func() { e.br, e.brErr = e.startBrowser(ctx) })
	if e.brErr != nil {
		return nil, nil, e.brErr
	}
	return e.br.browserCtx, e.br.browserCancel, nil
}

func (e *Env) startBrowser(ctx context.Context) (*browserEnv, error) {
	spki, err := spkiHash(e.frontLeaf.CertPath)
	if err != nil {
		return nil, err
	}
	profile := filepath.Join(e.root, "chrome")
	if err := os.Mkdir(profile, 0o700); err != nil {
		return nil, fmt.Errorf("identitytest: browser profile: %w", err)
	}
	b := &browserEnv{}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(e.h.cfg.ChromePath),
		chromedp.UserDataDir(profile),
		chromedp.Headless,
		chromedp.NoSandbox,
		chromedp.Flag("ignore-certificate-errors-spki-list", spki),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-crash-reporter", true),
		chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.cmd = cmd
		}),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(e.ctx, opts...)
	b.allocCancel = allocCancel
	b.browserCtx, b.browserCancel = chromedp.NewContext(allocCtx)
	// The first action starts the browser; the version is then asked of the
	// browser itself over CDP.
	err = chromedp.Do(b.browserCtx)
	var v browser.GetVersionResult
	if err == nil {
		v, err = cdp.Call(b.browserCtx, chromedp.FromContext(b.browserCtx).Browser, browser.GetVersion, cdp.Empty{})
	}
	if err == nil {
		var version string
		if version, err = checkChromeVersion(v.Product); err == nil {
			e.log.Info("browser started", "version", version, "pid", b.pid())
			return b, nil
		}
	} else {
		err = fmt.Errorf("identitytest: start the browser %s: %w", e.h.cfg.ChromePath, err)
	}
	return nil, errors.Join(err, b.close())
}

func (b *browserEnv) pid() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd == nil || b.cmd.Process == nil {
		return 0
	}
	return b.cmd.Process.Pid
}

// close stops Chrome through chromedp, which waits for it, then kills
// whatever is left of its process group: a helper (the zygote, the GPU or
// network process, a crash handler) can outlive the browser process.
func (b *browserEnv) close() error {
	b.browserCancel()
	b.allocCancel()
	pid := b.pid()
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("identitytest: kill the browser's process group %d: %w", pid, err)
	}
	return nil
}

// spkiHash is the base64 SHA-256 of a certificate's SubjectPublicKeyInfo,
// the form --ignore-certificate-errors-spki-list takes.
func spkiHash(certPath string) (string, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("identitytest: front leaf: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("identitytest: front leaf %s holds no PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("identitytest: front leaf: %w", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
