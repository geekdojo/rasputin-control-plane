package mesh

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// BuildIOSMobileConfig renders an Apple .mobileconfig payload (plist XML)
// that installs the provided PEM-encoded certificate as a root CA.
//
// The profile is unsigned. iOS will warn the user "Profile is Unsigned"
// on install; this is acceptable for a homelab-grade trust root that the
// operator is knowingly accepting. Signing requires an Apple-trusted
// developer cert, which is out of scope.
//
// Returns content-type `application/x-apple-aspen-config` payload bytes;
// the caller (HTTP handler) sets the Content-Type + Content-Disposition
// headers so iOS Safari prompts the install flow.
//
// The PayloadUUIDs are derived deterministically from the cert content
// (SHA-1 → first 16 bytes → RFC4122 v5-style hex layout). Stable UUIDs
// mean that re-downloading the same profile replaces an existing install
// instead of stacking duplicates.
func BuildIOSMobileConfig(rootPEM []byte, displayName, organization string) ([]byte, error) {
	if len(rootPEM) == 0 {
		return nil, errors.New("mesh: BuildIOSMobileConfig: empty cert PEM")
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("mesh: BuildIOSMobileConfig: input is not a PEM-encoded CERTIFICATE")
	}
	if displayName == "" {
		displayName = "Rasputin Internal Trust Root"
	}
	if organization == "" {
		organization = "Rasputin"
	}

	// Apple's <data> field expects base64 of DER, wrapped at 64 cols.
	certB64 := wrap(base64.StdEncoding.EncodeToString(block.Bytes), 64)

	outerUUID := stableUUID([]byte("rasputin-trust-outer:"), block.Bytes)
	innerUUID := stableUUID([]byte("rasputin-trust-inner:"), block.Bytes)

	const tmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadIdentifier</key>
	<string>com.geekdojo.rasputin.trust</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadDescription</key>
	<string>Installs the Rasputin internal root CA so iOS apps (e.g. Tailscale) trust the Headscale TLS endpoint.</string>
	<key>PayloadOrganization</key>
	<string>%s</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadIdentifier</key>
			<string>com.geekdojo.rasputin.trust.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadCertificateFileName</key>
			<string>rasputin-ca.crt</string>
			<key>PayloadContent</key>
			<data>
%s
			</data>
		</dict>
	</array>
</dict>
</plist>
`
	out := fmt.Sprintf(tmpl,
		outerUUID,
		xmlEscape(displayName),
		xmlEscape(organization),
		innerUUID,
		xmlEscape(displayName),
		indent(certB64, "\t\t\t\t"),
	)
	return []byte(out), nil
}

// stableUUID returns a deterministic, RFC-4122-shaped UUID string built
// from the SHA-1 of (prefix || certDER). Same cert ⇒ same UUID across
// requests, which is what iOS uses to replace an existing install.
func stableUUID(prefix, der []byte) string {
	h := sha1.New()
	h.Write(prefix)
	h.Write(der)
	sum := h.Sum(nil)[:16]
	// Stamp the version (5, name-based SHA-1) and variant (RFC-4122) bits
	// per RFC 4122 §4.3 so iOS's UUID parser accepts the value.
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // variant 10x
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// wrap inserts a newline every n characters. Apple's plist <data> is
// whitespace-tolerant but conventionally 64-column-wrapped.
func wrap(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		if end != len(s) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// indent prefixes every non-empty line with the given prefix. Used to
// align the base64 cert body with the surrounding plist indentation so
// the rendered XML stays human-readable.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// xmlEscape is the minimal set needed inside `<string>` plist nodes.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	)
	return r.Replace(s)
}
