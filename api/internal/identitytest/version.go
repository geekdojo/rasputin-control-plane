package identitytest

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// pinned is the version a release constant pins: the text after its last
// ':', which is how gatereg reads the same const.
func pinned(release string) string { return release[strings.LastIndex(release, ":")+1:] }

// checkKeycloakVersion runs `kc.sh --version` with JAVA_HOME set and refuses
// anything but the pinned Keycloak on the pinned JRE, so the service under
// test is the one the constants name. It returns the pinned Keycloak
// version and the JVM line kc.sh printed.
func (h *Harness) checkKeycloakVersion(ctx context.Context) (version, jvm string, err error) {
	kcsh := filepath.Join(h.cfg.KeycloakHome, "bin", "kc.sh")
	out, err := h.cfg.Run(ctx, "env", "JAVA_HOME="+h.cfg.JavaHome, "PATH=/usr/bin:/bin", kcsh, "--version")
	if err != nil {
		return "", "", fmt.Errorf("identitytest: %s --version: %w", kcsh, err)
	}
	if jvm, err = parseKeycloakVersion(string(out)); err != nil {
		return "", "", fmt.Errorf("identitytest: %s: %w", kcsh, err)
	}
	return pinned(KeycloakRelease), jvm, nil
}

// parseKeycloakVersion checks kc.sh --version's output, which 26.8.2 prints
// as (measured):
//
//	Keycloak 26.8.2
//	JVM: 25.0.5 (Eclipse Adoptium OpenJDK 64-Bit Server VM 25.0.5+8-LTS)
//	OS: Linux 6.8.0 amd64
func parseKeycloakVersion(out string) (jvm string, err error) {
	var kc string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Keycloak "):
			kc = strings.TrimPrefix(line, "Keycloak ")
		case strings.HasPrefix(line, "JVM: "):
			jvm = strings.TrimPrefix(line, "JVM: ")
		}
	}
	if kc == "" || jvm == "" {
		return "", fmt.Errorf("cannot read the Keycloak and JVM versions from its --version output %q", out)
	}
	if want := pinned(KeycloakRelease); kc != want {
		return "", fmt.Errorf("is not the pinned release: want Keycloak %s (%s), got Keycloak %s", want, KeycloakRelease, kc)
	}
	// The build is in the parenthesis ("… 25.0.5+8-LTS"), so match the
	// whole pinned release, build number included.
	if want := pinned(JRERelease); !strings.Contains(jvm, want) {
		return "", fmt.Errorf("is not on the pinned runtime: want JVM %s (%s), got JVM %s", want, JRERelease, jvm)
	}
	return jvm, nil
}

// checkChromeVersion compares the product CDP's Browser.getVersion reports
// ("HeadlessChrome/157.0.8103.78") with the pinned release.
func checkChromeVersion(product string) (string, error) {
	_, got, ok := strings.Cut(product, "/")
	if !ok || got == "" {
		return "", fmt.Errorf("identitytest: cannot read the browser version from %q", product)
	}
	if want := pinned(ChromeForTestingRelease); got != want {
		return "", fmt.Errorf("identitytest: the browser is not the pinned release: want Chrome for Testing %s (%s), got %s",
			want, ChromeForTestingRelease, product)
	}
	return got, nil
}
