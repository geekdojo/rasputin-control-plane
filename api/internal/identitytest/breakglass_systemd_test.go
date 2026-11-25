package identitytest

// CI TS-22 and IA-F9 (geekdojo/geekdojo-brain#321, TC-321-27 to TC-321-35):
// the break-glass repair session on the console stack (console_systemd_test.go),
// with the api's https listener on every address of the runner, so it
// answers at https://ci.local (mapped to 127.0.0.1:443) and at the runner's
// primary address, the LAN origin. With keycloak.service stopped, root makes
// codes with the real `rasputin-api repair-code` in a pty and redeems them
// from the Go client and in the pinned Chrome; RESTART brings the real
// Keycloak back; an administrator's normal sign-in and an api restart each
// end the session and retire the code.
//
// It needs what the console stack needs, plus util-linux's script and
// setpriv. Without them it skips, and under
// RASPUTIN_IDENTITY_SYSTEMD_FUNCTIONAL=required it fails (TC-321-35).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
)

const (
	// repairSocket is the repair-code socket the api serves on Linux.
	repairSocket    = "/run/rasputin-repair/repair-code.sock"
	repairCookie    = "__Host-rasputin-repair"
	breakGlassAdmin = "break-glass-admin-fixture"
	// clockSyncDir and clockSyncMarker are systemd-timesyncd's signal, as
	// the api reads it (cmd/rasputin-api main.go clockSyncDir).
	clockSyncDir    = "/run/systemd/timesync"
	clockSyncMarker = clockSyncDir + "/synchronized"
)

var (
	repairCodeRE = regexp.MustCompile(`\b[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}\b`)
	repairIPRE   = regexp.MustCompile(`https://(\d+\.\d+\.\d+\.\d+)/repair`)
)

// breakGlass is the test's state over the stack.
type breakGlass struct {
	t     *testing.T
	s     *consoleStack
	ctx   context.Context
	admin *idclient.Session
	// ip is the runner's primary address, as the api reports it.
	ip string
	// local reaches the api at 127.0.0.1; lan at the primary address.
	local, lan *http.Client
}

func TestIdentitySystemd_BreakGlass(t *testing.T) {
	for _, tool := range []string{"script", "setpriv"} {
		if _, err := exec.LookPath(tool); err != nil {
			functest.SkipOrFail(t, systemdSwitchEnv, "the break-glass test needs util-linux's %s: %v", tool, err)
			return
		}
	}
	s, ctx, admin := startConsoleStack(t, consoleStackOpts{allAddrs: true, clockSynced: true})
	if s == nil {
		return
	}
	if s.port != "443" {
		t.Fatalf("the break-glass test needs the api on :443 (the LAN origin has no port), not %s", s.port)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(filepath.Dir(repairSocket)); err != nil {
			t.Errorf("remove %s: %v", filepath.Dir(repairSocket), err)
		}
	})
	bg := &breakGlass{t: t, s: s, ctx: ctx, admin: admin, local: s.client(nil)}
	s.awaitFiles(ctx, "the api serves the repair-code socket", repairSocket)

	// Sign-in down.
	if out, err := s.pair.run(ctx, "systemctl", "stop", s.pair.KCUnit); err != nil {
		t.Fatalf("stop %s: %v: %s", s.pair.KCUnit, err, out)
	}

	bg.tc28NonRootAndNonTerminal()
	a := bg.code()
	bg.lan = s.clientAt(bg.ip+":443", nil)
	bg.tc29FiveWrong(a)
	s2 := bg.tc27GoRedeem()
	bg.tc31OnlyRepairRoutes(s2)
	bg.tc30ReuseAndDoors()
	chrome := bg.tc27ChromeAndTC32Restart()
	bg.tc33AdminSignIn(chrome)
	bg.tc34APIRestart()
}

// markClockSynced makes the clock-sync fact hold on the runner, which runs
// no systemd-timesyncd: the administrator fixture enrols an authenticator
// app, which converge enables only while the fact holds (TC-987-05). It
// writes timesyncd's marker, and its directory when absent, and removes
// only what it wrote at cleanup. A marker already there is left alone.
func markClockSynced(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(clockSyncMarker); err == nil {
		return
	}
	made := clockSyncMarker
	if _, err := os.Stat(clockSyncDir); errors.Is(err, os.ErrNotExist) {
		made = clockSyncDir
	}
	if err := os.MkdirAll(clockSyncDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clockSyncMarker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(made); err != nil {
			t.Errorf("remove %s: %v", made, err)
		}
	})
}

// code runs `rasputin-api repair-code` as root in a pty and returns the code
// it printed, recording the runner's address from the URLs it printed.
func (bg *breakGlass) code() string {
	bg.t.Helper()
	out, err := bg.repairCode(exec.CommandContext(bg.ctx, "script", "-qec", bg.s.apiBin+" repair-code", "/dev/null"))
	if err != nil {
		bg.t.Fatalf("repair-code in a pty: %v\n%s", err, out)
	}
	codes := repairCodeRE.FindAllString(out, -1)
	if len(codes) != 1 {
		bg.t.Fatalf("repair-code printed %d codes", len(codes))
	}
	if m := repairIPRE.FindStringSubmatch(out); m != nil {
		bg.ip = m[1]
	} else if bg.ip == "" {
		bg.t.Fatalf("repair-code printed no LAN address:\n%s", repairCodeRE.ReplaceAllString(out, "<code>"))
	}
	return codes[0]
}

// repairCode runs cmd with the api's data dir, and returns its output.
func (bg *breakGlass) repairCode(cmd *exec.Cmd) (string, error) {
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + bg.s.work, "TERM=dumb", "RASPUTIN_DATA_DIR=" + bg.s.dataDir}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// call sends one request through c and returns the status, the body and the
// response's cookies.
func (bg *breakGlass) call(c *http.Client, method, u, body string, header http.Header, cookies ...*http.Cookie) (int, []byte, []*http.Cookie) {
	bg.t.Helper()
	req, err := http.NewRequestWithContext(bg.ctx, method, u, strings.NewReader(body))
	if err != nil {
		bg.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := c.Do(req)
	if err != nil {
		bg.t.Fatalf("%s %s: %v", method, u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Cookies()
}

// redeem posts code to origin's break-glass route through c.
func (bg *breakGlass) redeem(c *http.Client, origin, code string) (int, string, *http.Cookie) {
	bg.t.Helper()
	body, _ := json.Marshal(map[string]string{"code": code})
	status, b, cookies := bg.call(c, http.MethodPost, origin+"/api/auth/break-glass", string(body), nil)
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &e)
	for _, ck := range cookies {
		if ck.Name == repairCookie && ck.Value != "" {
			return status, e.Code, ck
		}
	}
	return status, e.Code, nil
}

// db opens rasputin.db read-only.
func (bg *breakGlass) db() *sql.DB {
	bg.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(bg.s.dataDir, "rasputin.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		bg.t.Fatal(err)
	}
	bg.t.Cleanup(func() { _ = db.Close() })
	return db
}

// count is one COUNT(*) query's answer.
func (bg *breakGlass) count(q string, args ...any) int {
	bg.t.Helper()
	var n int
	if err := bg.db().QueryRowContext(bg.ctx, q, args...).Scan(&n); err != nil {
		bg.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// alerts is the number of persisted alert rows named name.
func (bg *breakGlass) alerts(name string) int {
	return bg.count(`SELECT COUNT(*) FROM persisted_alerts WHERE labels LIKE ?`, `%"alertname":"`+name+`"%`)
}

// apiLog is the api's log so far.
func (bg *breakGlass) apiLog() string {
	b, _ := os.ReadFile(filepath.Join(bg.s.out, "api.log"))
	return string(b)
}

// logHas reports whether one line of the api's log holds every part.
func (bg *breakGlass) logHas(parts ...string) bool {
	for _, line := range strings.Split(bg.apiLog(), "\n") {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(line, p)
		}
		if all {
			return true
		}
	}
	return false
}

// TC-321-28: nobody in a pty, and root with stdout to a file, are refused
// with no code printed; nothing was issued, so a redemption is 401
// repair_code_none and no issue alert exists.
func (bg *breakGlass) tc28NonRootAndNonTerminal() {
	t := bg.t
	out, err := bg.repairCode(exec.CommandContext(bg.ctx, "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
		"script", "-qec", bg.s.apiBin+" repair-code", "/dev/null"))
	if err == nil || repairCodeRE.MatchString(out) {
		t.Errorf("TC-321-28: repair-code as nobody: err %v, printed a code: %v", err, repairCodeRE.MatchString(out))
	}
	f, err := os.Create(filepath.Join(bg.s.work, "repair-code.out"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(bg.ctx, bg.s.apiBin, "repair-code")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "RASPUTIN_DATA_DIR=" + bg.s.dataDir}
	cmd.Stdout = f
	runErr := cmd.Run()
	_ = f.Close()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 2 {
		t.Errorf("TC-321-28: repair-code to a file: %v, want exit 2", runErr)
	}
	if b, _ := os.ReadFile(f.Name()); len(b) != 0 {
		t.Errorf("TC-321-28: repair-code wrote %d bytes to the file", len(b))
	}
	if status, code, _ := bg.redeem(bg.local, "https://"+consoleCID+".local", "ABCDE-FGHIJ-KLMNO-PQRST"); status != http.StatusUnauthorized || code != "repair_code_none" {
		t.Errorf("TC-321-28: a redemption after the refusals: %d %s, want 401 repair_code_none", status, code)
	}
	if n := bg.alerts("BreakGlassCodeIssued"); n != 0 {
		t.Errorf("TC-321-28: %d issue alerts after the refusals, want 0", n)
	}
}

// TC-321-29: five wrong codes from 127.0.0.1 answer 401, the sixth 429; the
// right code from the runner's address opens a session.
func (bg *breakGlass) tc29FiveWrong(a string) {
	t := bg.t
	origin := "https://" + consoleCID + ".local"
	for i := range 5 {
		if status, code, _ := bg.redeem(bg.local, origin, "WRONG-WRONG-WRONG-WRONG"); status != http.StatusUnauthorized || code != "repair_code_wrong" {
			t.Fatalf("TC-321-29: wrong code %d: %d %s", i+1, status, code)
		}
	}
	if status, code, _ := bg.redeem(bg.local, origin, a); status != http.StatusTooManyRequests || code != "repair_source_refused" {
		t.Fatalf("TC-321-29: the sixth from 127.0.0.1: %d %s, want 429", status, code)
	}
	if status, code, c := bg.redeem(bg.lan, "https://"+bg.ip, a); status != http.StatusOK || c == nil {
		t.Fatalf("TC-321-29: the right code from %s: %d %s", bg.ip, status, code)
	}
	if !bg.logHas("breakglass.redeem_refused", "source=127.0.0.1", "reason=wrong_code") ||
		!bg.logHas("breakglass.redeem_refused", "source=127.0.0.1", "reason=source_refused") {
		t.Error("TC-321-29: no redeem_refused records with source=127.0.0.1")
	}
}

// TC-321-27 (the Go leg): a code redeems at https://ci.local.
func (bg *breakGlass) tc27GoRedeem() *http.Cookie {
	status, code, c := bg.redeem(bg.local, "https://"+consoleCID+".local", bg.code())
	if status != http.StatusOK || c == nil {
		bg.t.Fatalf("TC-321-27: redeem at ci.local: %d %s", status, code)
	}
	return c
}

// TC-321-31: with a repair session, a node reboot, a power cycle and the
// node list answer 403 repair_only, and no job row is made.
func (bg *breakGlass) tc31OnlyRepairRoutes(sess *http.Cookie) {
	t := bg.t
	before := bg.count(`SELECT COUNT(*) FROM jobs`)
	origin := "https://" + consoleCID + ".local"
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/jobs", `{"kind":"node.reboot","spec":{"nodeId":"ci-node"}}`},
		{http.MethodPost, "/api/bmc/ci-node/power/cycle", ""},
		{http.MethodGet, "/api/nodes", ""},
	} {
		status, b, _ := bg.call(bg.local, c.method, origin+c.path, c.body, nil, sess)
		if status != http.StatusForbidden || !strings.Contains(string(b), `"repair_only"`) {
			t.Errorf("TC-321-31: %s %s: %d %s, want 403 repair_only", c.method, c.path, status, b)
		}
	}
	if after := bg.count(`SELECT COUNT(*) FROM jobs`); after != before {
		t.Errorf("TC-321-31: the jobs table went from %d rows to %d", before, after)
	}
}

// TC-321-30: reuse is refused; neither sign-in door sets a repair cookie,
// and the code they were sent still works; a console route at the address
// answers 403 origin not allowed.
func (bg *breakGlass) tc30ReuseAndDoors() {
	t := bg.t
	origin := "https://" + consoleCID + ".local"
	b := bg.code()
	if status, _, c := bg.redeem(bg.local, origin, b); status != http.StatusOK || c == nil {
		t.Fatalf("TC-321-30: the first redemption: %d", status)
	}
	if status, code, _ := bg.redeem(bg.local, origin, b); status != http.StatusUnauthorized || code != "repair_code_none" {
		t.Errorf("TC-321-30: reuse: %d %s, want 401 repair_code_none", status, code)
	}
	table, err := doors.New(consoleCID)
	if err != nil {
		t.Fatal(err)
	}
	c := bg.code()
	for _, host := range []string{table.Home.Host, table.App.Host} {
		if status, _, ck := bg.redeem(bg.local, "https://"+host, c); ck != nil {
			t.Errorf("TC-321-30: the door at %s set a repair cookie (%d)", host, status)
		}
	}
	status, body, _ := bg.call(bg.lan, http.MethodPost, "https://"+bg.ip+"/api/jobs", `{"kind":"node.reboot"}`,
		http.Header{"Origin": {"https://" + bg.ip}})
	if status != http.StatusForbidden || !strings.Contains(string(body), "origin not allowed") {
		t.Errorf("TC-321-30: a console route at the address: %d %s, want 403 origin not allowed", status, body)
	}
	if status, code, ck := bg.redeem(bg.local, origin, c); status != http.StatusOK || ck == nil {
		t.Errorf("TC-321-30: the code sent to the doors: %d %s, want it still outstanding", status, code)
	}
}

// TC-321-27 (the Chrome leg) and TC-321-32: a code redeems at
// https://<address>/repair in the pinned Chrome, which then shows the state
// and RESTART; RESTART makes identity.restart by break-glass, which
// succeeds, keycloak.service is active, sign-in is ready, and the page shows
// the job finished. Both event alerts are in rasputin.db.
func (bg *breakGlass) tc27ChromeAndTC32Restart() *http.Cookie {
	t := bg.t
	code := bg.code()
	front := "https://" + bg.ip
	tb := newTab(t, bg.s.browser(bg.ctx), front)
	tb.navigate(front + "/repair")
	tb.step(chromedp.WaitVisible(chromedp.ID("repair-code")), "wait for the repair code field")
	tb.step(chromedp.SendKeys(chromedp.ID("repair-code"), code), "type the repair code")
	tb.step(chromedp.Click(chromedp.Search(`//button[normalize-space(.)="OPEN REPAIR SESSION"]`)), "press OPEN REPAIR SESSION")
	tb.step(chromedp.WaitVisible(chromedp.Search(`//button[normalize-space(.)="RESTART"]`)), "wait for RESTART")
	bg.screenshot(tb, "repair.png")

	cctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	res, err := chromedp.Call(cctx, network.GetCookies, network.GetCookiesParams{URLs: []string{front + "/"}})
	if err != nil {
		t.Fatal(err)
	}
	var sess *http.Cookie
	for _, c := range res.Cookies {
		if c.Name == repairCookie {
			sess = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	if sess == nil {
		t.Fatal("TC-321-27: Chrome holds no repair session at the address")
	}
	if bg.alerts("BreakGlassCodeIssued") == 0 || bg.alerts("BreakGlassSessionOpened") == 0 {
		t.Errorf("TC-321-27: issue alerts %d, session alerts %d; want both", bg.alerts("BreakGlassCodeIssued"), bg.alerts("BreakGlassSessionOpened"))
	}

	tb.step(chromedp.Click(chromedp.Search(`//button[normalize-space(.)="RESTART"]`)), "press RESTART")
	err = proctest.Await(bg.ctx, nil, func(context.Context) (bool, string, error) {
		if err := bg.s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		text := evalT[string](tb, `document.body ? document.body.innerText : ''`)
		switch {
		case strings.Contains(text, "identity.restart — succeeded"):
			return true, "", nil
		case strings.Contains(text, "identity.restart — failed"):
			return false, "", &proctest.Final{Err: fmt.Errorf("the restart failed: %s", text)}
		}
		return false, "the page does not show the restart finished", nil
	}, func(last string) { bg.s.cfg.Logger.Info("break-glass: waiting for the restart", "last", last) })
	if err != nil {
		t.Fatal(errNamed("TC-321-32: /repair shows identity.restart succeeded", err))
	}
	bg.screenshot(tb, "repair-restarted.png")
	var status, by string
	if err := bg.db().QueryRowContext(bg.ctx, `SELECT status, created_by FROM jobs WHERE kind = 'identity.restart'`).Scan(&status, &by); err != nil ||
		status != "succeeded" || by != "break-glass" {
		t.Errorf("TC-321-32: the identity.restart row: %s by %s (%v)", status, by, err)
	}
	bg.s.awaitReady(bg.ctx, bg.admin)
	if st, err := unitState(bg.ctx, bg.s.pair.run, bg.s.pair.KCUnit); err != nil || st != "active/running" {
		t.Errorf("TC-321-32: %s is %s (%v)", bg.s.pair.KCUnit, st, err)
	}
	return sess
}

// screenshot writes the tab's page to <out>/shots/name.
func (bg *breakGlass) screenshot(tb *tab, name string) {
	sctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	png, err := chromedp.Run(sctx, chromedp.FullScreenshot(90))
	if err != nil {
		bg.t.Fatalf("screenshot: %v", err)
	}
	shot := filepath.Join(bg.s.out, "shots", name)
	if err := os.MkdirAll(filepath.Dir(shot), 0o700); err != nil {
		bg.t.Fatal(err)
	}
	if err := os.WriteFile(shot, png, 0o600); err != nil {
		bg.t.Fatal(err)
	}
	bg.t.Logf("screenshot %s (%d bytes)", shot, len(png))
}

// TC-321-33: with Chrome's repair session live and a code outstanding, an
// administrator's normal sign-in through the launcher ends the session and
// retires the code.
func (bg *breakGlass) tc33AdminSignIn(sess *http.Cookie) {
	t := bg.t
	outstanding := bg.code()
	bg.signInAdmin()
	status, _, _ := bg.call(bg.lan, http.MethodGet, "https://"+bg.ip+"/api/repair/state", "", nil, sess)
	if status != http.StatusUnauthorized {
		t.Errorf("TC-321-33: the repair session after an administrator's sign-in: %d, want 401", status)
	}
	if status, code, _ := bg.redeem(bg.local, "https://"+consoleCID+".local", outstanding); status != http.StatusUnauthorized || code != "repair_code_none" {
		t.Errorf("TC-321-33: the outstanding code: %d %s, want 401 repair_code_none", status, code)
	}
	if !bg.logHas("breakglass.session_ended", "reason=admin_signin") || !bg.logHas("breakglass.code_retired", "reason=admin_signin") {
		t.Error("TC-321-33: no session_ended and code_retired records with reason=admin_signin")
	}
}

// signInAdmin makes a synthetic administrator with an authenticator app and
// signs it in through the launcher with its password and a code. The
// account enrols the app on a first sign-in, holding no role; once the api
// has marked its second step, it is granted admin and signs in again.
func (bg *breakGlass) signInAdmin() {
	t := bg.t
	ctx := t.Context()
	pw, err := randomSecret(bg.s.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Destroy()
	// The enrolment needs the authenticator app offered: converge enables
	// CONFIGURE_TOTP once it reads the clock-sync fact (markClockSynced).
	err = proctest.Await(bg.ctx, nil, func(ctx context.Context) (bool, string, error) {
		var a struct {
			Enabled bool `json:"enabled"`
		}
		if _, err := bg.admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/authentication/required-actions/"+flows.ActionConfigureTOTP, nil, &a); err != nil {
			return false, err.Error(), nil
		}
		return a.Enabled, "CONFIGURE_TOTP is disabled", nil
	}, func(last string) {
		bg.s.cfg.Logger.Info("break-glass: waiting for the authenticator app to be enabled", "last", last)
	})
	if err != nil {
		t.Fatal(errNamed("converge enabled CONFIGURE_TOTP for the administrator fixture", err))
	}
	resp, err := bg.admin.Admin(ctx, http.MethodPost, "/admin/realms/"+baselineRealm+"/users", map[string]any{
		"username": breakGlassAdmin, "enabled": true, "email": breakGlassAdmin + "@console.invalid", "emailVerified": true,
		"firstName": "Break", "lastName": "Glass", "requiredActions": []string{flows.ActionConfigureTOTP},
		"credentials": []map[string]any{{"type": "password", "value": string(pw.Reveal()), "temporary": false}},
	}, nil)
	if err != nil {
		t.Fatalf("create the administrator fixture: %v", err)
	}
	id := resp.Location[strings.LastIndex(resp.Location, "/")+1:]
	codes := &totpCodes{used: map[string]bool{}}
	var secretB32 string
	steps := func(p signin.Page, body []byte) (string, map[string]string, error) {
		switch p.ID {
		case "login-login-config-totp":
			m := regexp.MustCompile(`<img id="kc-totp-secret-qr-code" src="([^"]*)"`).FindSubmatch(body)
			if m == nil {
				return "", nil, errors.New("the setup page shows no QR code")
			}
			text, err := decodeQR(html.UnescapeString(string(m[1])))
			if err != nil {
				return "", nil, err
			}
			u, err := url.Parse(text)
			if err != nil || u.Scheme != "otpauth" {
				return "", nil, errors.New("the QR code holds no otpauth URI")
			}
			secretB32 = u.Query().Get("secret")
			return "kc-totp-settings-form", map[string]string{"totp": codes.next(t, secretB32), "userLabel": "Break-glass phone"}, nil
		case "login-login-otp":
			return "kc-otp-login-form", map[string]string{"otp": codes.next(t, secretB32)}, nil
		case "login-login-recovery-authn-code-config":
			return "kc-recovery-codes-settings-form", nil, nil
		}
		return "", nil, fmt.Errorf("unexpected page %s", p.ID)
	}
	c := signin.Console{Origin: "https://" + consoleCID + ".local", Transport: admitted{next: bg.local.Transport, log: bg.s.cfg.Logger},
		Logger: bg.s.cfg.Logger, Steps: steps}
	var refused *signin.ConsoleRefusedError
	_, pages, err := signin.ConsoleSignIn(ctx, c, breakGlassAdmin, pw)
	if err != nil && !errors.As(err, &refused) {
		t.Fatalf("the administrator fixture's enrolment (pages %v): %v", pages, err)
	}
	if secretB32 == "" {
		t.Fatalf("the enrolment sign-in showed no authenticator app setup (pages %v)", pages)
	}
	err = proctest.Await(bg.ctx, nil, func(ctx context.Context) (bool, string, error) {
		var u struct {
			Attributes map[string][]string `json:"attributes"`
		}
		if _, err := bg.admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/users/"+id, nil, &u); err != nil {
			return false, err.Error(), nil
		}
		if v := u.Attributes[flows.MarkerSecondStepHome]; len(v) == 1 && v[0] == "true" {
			return true, "", nil
		}
		return false, "the second-step marker is not set", nil
	}, func(last string) {
		bg.s.cfg.Logger.Info("break-glass: waiting for the second-step marker", "last", last)
	})
	if err != nil {
		t.Fatal(errNamed("the api marked the administrator fixture's second step", err))
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if _, err := bg.admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/clients?clientId="+baselineConsole, nil, &clients); err != nil || len(clients) != 1 {
		t.Fatalf("the console client: %v", err)
	}
	var role map[string]any
	if _, err := bg.admin.Admin(ctx, http.MethodGet, "/admin/realms/"+baselineRealm+"/clients/"+clients[0].ID+"/roles/admin", nil, &role); err != nil {
		t.Fatal(err)
	}
	if _, err := bg.admin.Admin(ctx, http.MethodPost, "/admin/realms/"+baselineRealm+"/users/"+id+"/role-mappings/clients/"+clients[0].ID, []any{role}, nil); err != nil {
		t.Fatal(err)
	}
	// So the grant's event cannot end the sign-in about to be made, as for
	// the console fixture (F-989-19).
	bg.s.awaitGrantDrained(bg.ctx, bg.admin, id)
	jar, pages, err := signin.ConsoleSignIn(ctx, c, breakGlassAdmin, pw)
	if err != nil {
		t.Fatalf("the administrator's sign-in (pages %v): %v", pages, err)
	}
	u, _ := url.Parse("https://" + consoleCID + ".local/")
	for _, ck := range jar.Cookies(u) {
		if ck.Name == auth.SessionCookieName {
			return
		}
	}
	t.Fatal("the administrator's sign-in left no console session")
}

// doorBusy is the start of the home door's answer to a credential post while
// the source's previous one is still being checked (policy.sentenceBusy).
const doorBusy = "Another sign-in from this device is still being checked."

// admitted sends each request through next, and re-sends a POST the home
// door answered 429 busy until the door admits it. The door holds one
// credential post per source and releases the slot on its next drain pass
// after the answer, so the code post that follows a password post at once
// finds the slot held. No request of the test's sees the release, so the
// door's admission of the post is the fact waited on; the test's context
// bounds the wait.
type admitted struct {
	next http.RoundTripper
	log  *slog.Logger
}

func (a admitted) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.GetBody == nil {
		return a.next.RoundTrip(req)
	}
	if req.Body != nil {
		_ = req.Body.Close() // every send below is from GetBody
	}
	var resp *http.Response
	err := proctest.Await(req.Context(), nil, func(context.Context) (bool, string, error) {
		body, err := req.GetBody()
		if err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		r := req.Clone(req.Context())
		r.Body = body
		out, err := a.next.RoundTrip(r)
		if err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		if out.StatusCode != http.StatusTooManyRequests {
			resp = out
			return true, "", nil
		}
		b, err := io.ReadAll(io.LimitReader(out.Body, 1<<20))
		_ = out.Body.Close()
		if err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		if !strings.Contains(string(b), doorBusy) {
			// Any other 429 is the caller's to read.
			out.Body = io.NopCloser(bytes.NewReader(b))
			resp = out
			return true, "", nil
		}
		return false, "the door holds the source's previous credential post", nil
	}, func(last string) {
		a.log.Info("break-glass: waiting for the door to admit a credential post", "last", last)
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// TC-321-34: an api restart ends the session and retires the outstanding
// code.
func (bg *breakGlass) tc34APIRestart() {
	t := bg.t
	origin := "https://" + consoleCID + ".local"
	status, code, sess := bg.redeem(bg.local, origin, bg.code())
	if status != http.StatusOK || sess == nil {
		t.Fatalf("TC-321-34: redeem: %d %s", status, code)
	}
	outstanding := bg.code()
	_ = syscall.Kill(-bg.s.api.Process.Pid, syscall.SIGTERM)
	select {
	case <-bg.s.apiDone:
	case <-time.After(60 * time.Second): // bounds the stop only
		t.Fatal("TC-321-34: the api did not stop within 60 s of SIGTERM")
	}
	bg.s.startAPI(bg.s.apiBin)
	bg.local = bg.s.client(nil)
	err := proctest.Await(bg.ctx, nil, func(context.Context) (bool, string, error) {
		if err := bg.s.apiAlive(); err != nil {
			return false, "", &proctest.Final{Err: err}
		}
		if _, err := os.Stat(repairSocket); err != nil {
			return false, "no repair-code socket", nil
		}
		resp, err := bg.local.Get(origin + "/api/auth/status")
		if err != nil {
			return false, err.Error(), nil
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK, fmt.Sprintf("status %d", resp.StatusCode), nil
	}, func(last string) { bg.s.cfg.Logger.Info("break-glass: waiting for the restarted api", "last", last) })
	if err != nil {
		t.Fatal(errNamed("TC-321-34: the restarted api serves https and the repair-code socket", err))
	}
	if status, _, _ := bg.call(bg.local, http.MethodGet, origin+"/api/repair/state", "", nil, sess); status != http.StatusUnauthorized {
		t.Errorf("TC-321-34: the session after an api restart: %d, want 401", status)
	}
	if status, code, _ := bg.redeem(bg.local, origin, outstanding); status != http.StatusUnauthorized || code != "repair_code_none" {
		t.Errorf("TC-321-34: the code after an api restart: %d %s, want 401 repair_code_none", status, code)
	}
}
