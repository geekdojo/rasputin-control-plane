// Command consoleshots screenshots pages of the console the recipe's stack
// serves (scripts/identity-on-mac.sh shots, geekdojo/geekdojo-brain#989),
// signed in, in a native browser: Chrome for Testing at the version CI pins,
// for mac-arm64, because the pinned linux64 build aborts under Apple
// silicon's amd64 emulation. It runs on the Mac, outside the recipe's
// container.
//
// It reads the stack's output directory: ready (the api's https port),
// api-spki (the api leaf's SPKI hash, the only certificate the browser
// accepts) and session.cookie (the synthetic fixture's console session).
// The browser maps ci.local:443 to 127.0.0.1:<port>, sets the session
// cookie, and screenshots each named path into <out>/shots. A path that
// lands on /login, or any response that answers 401, fails the run.
//
// Usage: consoleshots -out data/identity-on-mac PATH...
package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
)

const (
	host = "ci.local"
	// stepTimeout bounds one navigation or one command. It is an I/O bound:
	// each step waits on the page's own network-idle event.
	stepTimeout = 2 * time.Minute
)

func main() {
	out := flag.String("out", "data/identity-on-mac", "the stack's output directory")
	cache := flag.String("cache", filepath.Join(os.Getenv("HOME"), ".cache", "rasputin-identity"), "where the browser is installed")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log, *out, *cache, flag.Args()); err != nil {
		log.Error("consoleshots failed", "err", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger, out, cache string, paths []string) error {
	if len(paths) == 0 {
		return errors.New("name at least one console path to screenshot, such as /")
	}
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			return "", fmt.Errorf("the stack is not up (run identity-on-mac.sh up): %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	port, err := read("ready")
	if err != nil {
		return err
	}
	spki, err := read("api-spki")
	if err != nil {
		return err
	}
	cookie, err := read("session.cookie")
	if err != nil {
		return err
	}
	chrome, err := installChrome(log, cache)
	if err != nil {
		return err
	}
	profile, err := os.MkdirTemp("", "consoleshots-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(profile) }()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chrome),
		chromedp.UserDataDir(profile),
		chromedp.Headless,
		chromedp.WindowSize(1440, 900),
		chromedp.Flag("host-resolver-rules", "MAP "+host+":443 127.0.0.1:"+port),
		chromedp.Flag("ignore-certificate-errors-spki-list", spki),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var mu sync.Mutex
	var refused []string
	if err := chromedp.Listen(ctx, func(ev any) {
		if e, ok := ev.(*network.EventResponseReceived); ok && e.Response.Status == http.StatusUnauthorized {
			mu.Lock()
			refused = append(refused, e.Response.URL)
			mu.Unlock()
		}
	}); err != nil {
		return err
	}
	step := func(what string, f func(context.Context) error) error {
		sctx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()
		if err := f(sctx); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	}
	if err := step("start the browser", func(c context.Context) error {
		if _, err := chromedp.Call(c, network.Enable, network.EnableParams{}); err != nil {
			return err
		}
		if _, err := chromedp.Call(c, page.SetLifecycleEventsEnabled, page.SetLifecycleEventsEnabledParams{Enabled: true}); err != nil {
			return err
		}
		_, err := chromedp.Call(c, network.SetCookie, network.SetCookieParams{
			Name: auth.SessionCookieName, Value: cookie, URL: "https://" + host + "/", Path: "/",
			Secure: new(true), HTTPOnly: new(true), SameSite: network.CookieSameSiteLax,
		})
		return err
	}); err != nil {
		return err
	}
	shots := filepath.Join(out, "shots")
	if err := os.MkdirAll(shots, 0o700); err != nil {
		return err
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		var png []byte
		var landed string
		err := step("screenshot "+p, func(c context.Context) error {
			idle := func(e page.EventLifecycleEvent) bool { return e.Name == "networkIdle" }
			if _, err := chromedp.Run(c, chromedp.WaitEvent(page.LifecycleEvent, idle, chromedp.Navigate("https://"+host+p))); err != nil {
				return err
			}
			var err error
			if landed, err = chromedp.Run(c, chromedp.Evaluate[string](`location.pathname`)); err != nil {
				return err
			}
			png, err = chromedp.Run(c, chromedp.FullScreenshot(90))
			return err
		})
		if err != nil {
			return err
		}
		mu.Lock()
		got := append([]string(nil), refused...)
		mu.Unlock()
		switch {
		case landed == "/login":
			return fmt.Errorf("%s landed on /login: the session is not signed in (run identity-on-mac.sh up again)", p)
		case len(got) > 0:
			return fmt.Errorf("%s: a request answered 401: %s", p, strings.Join(got, ", "))
		}
		file := filepath.Join(shots, shotName(p))
		if err := os.WriteFile(file, png, 0o600); err != nil {
			return err
		}
		log.Info("screenshot", "path", p, "file", file, "bytes", len(png))
	}
	return nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// shotName is a path's screenshot file name.
func shotName(p string) string {
	n := strings.Trim(unsafeName.ReplaceAllString(p, "_"), "_")
	if n == "" {
		n = "root"
	}
	return n + ".png"
}

// installChrome installs Chrome for Testing for mac-arm64 at the version CI
// pins into cache, checked against identitytest.ChromeMacArm64SHA256, and
// returns its executable. An installed copy is used as it is.
func installChrome(log *slog.Logger, cache string) (string, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return "", fmt.Errorf("consoleshots runs on a Mac with Apple silicon; this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	version := identitytest.ChromeForTestingRelease[strings.LastIndex(identitytest.ChromeForTestingRelease, ":")+1:]
	dir := filepath.Join(cache, "chrome-mac-arm64-"+version)
	exe := filepath.Join(dir, "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing")
	if _, err := os.Stat(exe); err == nil {
		return exe, nil
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", err
	}
	zipPath := filepath.Join(cache, "chrome-mac-arm64-"+version+".zip")
	url := "https://storage.googleapis.com/chrome-for-testing-public/" + version + "/mac-arm64/chrome-mac-arm64.zip"
	log.Info("downloading the browser", "url", url)
	if err := download(url, zipPath); err != nil {
		return "", err
	}
	sum, err := fileSHA256(zipPath)
	if err != nil {
		return "", err
	}
	if sum != identitytest.ChromeMacArm64SHA256 {
		return "", fmt.Errorf("%s has sha256 %s, not the pinned %s; refusing it (it is left in place)", zipPath, sum, identitytest.ChromeMacArm64SHA256)
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("%s is not a zip: %w", zipPath, err)
	}
	_ = zr.Close()
	// ditto keeps the app bundle's links and attributes, which a plain
	// extraction loses.
	if out, err := exec.Command("/usr/bin/ditto", "-x", "-k", zipPath, dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("extract %s: %w: %s", zipPath, err, out)
	}
	if err := os.Remove(zipPath); err != nil {
		return "", err
	}
	return exe, nil
}

func download(url, dst string) error {
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Get(url) // bounds the download only
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	f, err := os.Create(dst + ".part")
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(dst+".part", dst)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
