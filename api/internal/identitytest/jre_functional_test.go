package identitytest_test

// The headless-JRE capability row (T72, geekdojo/geekdojo-brain#969): under
// the unit's -Djava.awt.headless=true, Keycloak on the pinned JRE renders the
// authenticator-code QR on its CONFIGURE_TOTP page. It shares pkg and
// TestMain with selftest_functional_test.go, and sorts before it, so
// TestIdentity_NoSecretInLogs still runs last and scans what this test typed.

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
)

// qrPrefix is how Keycloak's login-config-totp.ftl starts the QR image's src.
const qrPrefix = "data:image/png;base64,"

// TC-969-18, TC-969-21: the pinned Chrome signs the harness user in with
// kc_action=CONFIGURE_TOTP; the setup page is login-login-config-totp and its
// QR is a data:image/png URI that decodes as a PNG with non-empty bounds. The
// test never submits the enrolment form, so the harness user gets no OTP
// credential and later sign-ins still see [login-login]. It runs in a browser
// context of its own, so no cookie it collects reaches TestIdentity_Browser.
func TestIdentity_TOTPQRUnderHeadlessJRE(t *testing.T) {
	shared, env := pkg.Browser(t)
	ctx, cancel := chromedp.NewContext(shared, chromedp.WithNewBrowserContext())
	defer cancel()
	name, password := env.User()

	q := url.Values{
		"client_id": {identitytest.ClientID}, "redirect_uri": {identitytest.RedirectURI},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"totp-qr-state"},
		"code_challenge": {signin.Challenge("totp-qr-verifier-totp-qr-verifier-totp-qr-verifier")}, "code_challenge_method": {"S256"},
		"prompt": {"login"}, "kc_action": {"CONFIGURE_TOTP"},
	}
	if err := chromedp.Do(ctx, chromedp.Navigate(env.Issuer()+"/protocol/openid-connect/auth?"+q.Encode())); err != nil {
		t.Fatalf("navigate to the authorization endpoint: %v", err)
	}
	// SetValue waits for its node, so the sign-in page is checked first:
	// any other page fails here instead of hanging.
	if got := pageID(t, ctx); got != "login-login" {
		t.Fatalf("before sign-in: data-page-id = %q, want login-login (page error: %q)", got, pageError(t, ctx))
	}

	resp, err := chromedp.RunResponse(ctx,
		chromedp.SetValue(chromedp.ID("username"), name),
		chromedp.SetValue(chromedp.ID("password"), string(password.Reveal())),
		chromedp.Click(chromedp.ID("kc-login")),
	)
	if err != nil {
		t.Fatalf("submit the sign-in form: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("after sign-in: document status = %d, want 200", resp.Status)
	}
	if got := pageID(t, ctx); got != "login-login-config-totp" {
		t.Fatalf("after sign-in: data-page-id = %q, want login-login-config-totp (page error: %q)", got, pageError(t, ctx))
	}

	src, err := chromedp.Run(ctx, chromedp.Evaluate[string](
		`document.getElementById('kc-totp-secret-qr-code')?.getAttribute('src') ?? ""`))
	if err != nil {
		t.Fatalf("read the QR image's src: %v", err)
	}
	if src == "" {
		t.Fatal("the setup page has no kc-totp-secret-qr-code src")
	}
	payload, ok := strings.CutPrefix(src, qrPrefix)
	if !ok {
		t.Fatalf("QR src starts %q, want the prefix %q", src[:min(32, len(src))], qrPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		t.Fatalf("decode the QR's base64 payload: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode the QR as a PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() == 0 || b.Dy() == 0 {
		t.Fatalf("QR PNG bounds = %v, want non-zero width and height", b)
	}
}

// pageID is the body's data-page-id, or "" when the page has none. Evaluate
// returns at once, so a missing node cannot hang the test.
func pageID(t *testing.T, ctx context.Context) string {
	t.Helper()
	return evalString(t, ctx, `document.body?.getAttribute('data-page-id') ?? ""`)
}

// pageError is the text of Keycloak's page-level or field-level error, for
// the failure message.
func pageError(t *testing.T, ctx context.Context) string {
	t.Helper()
	return evalString(t, ctx, `(document.getElementById('kc-error-message') ?? document.querySelector('[id^="input-error"]'))?.textContent?.trim() ?? ""`)
}

// evalString runs a JavaScript expression that yields a string. A failed
// evaluation is reported in the string, since it only feeds a failure message
// or a comparison that then fails.
func evalString(t *testing.T, ctx context.Context, expr string) string {
	t.Helper()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[string](expr))
	if err != nil {
		return "evaluate failed: " + err.Error()
	}
	return v
}
