package apps

import (
	"errors"
	"testing"
)

// The web-port loopback rule on a custom app's compose
// (geekdojo/geekdojo-brain#1091).

const (
	msgEveryInterface = `Web port 8080 is published on every interface, not loopback: write it as "127.0.0.1:8080:<container>" so only the node proxy reaches it.`
	msgNotPublished   = `Web port 8080 is not published: add "127.0.0.1:8080:<container>" to the service that serves it.`
	msgUncheckable    = `Web port 8080 is not published in a form that can be checked: write it as "127.0.0.1:8080:<container>", with no protocol suffix, variable or long syntax.`
)

func msgOtherHost(host string) string {
	return `Web port 8080 is published on ` + host + `, not loopback: write it as "127.0.0.1:8080:<container>" so only the node proxy reaches it.`
}

// bindRefusal asserts err is a *WebPortBindError and returns its text.
func bindRefusal(t *testing.T, compose string, err error) string {
	t.Helper()
	var be *WebPortBindError
	if !errors.As(err, &be) {
		t.Fatalf("%q: err = %v, want a *WebPortBindError", compose, err)
	}
	return be.Error()
}

// TC-1091-01: port 0 is not validated, so neither invalid YAML nor a
// non-loopback publish is read.
func TestCheckWebPortPublish_NoPortIsNotChecked(t *testing.T) {
	for _, c := range []string{"services: [", `services: {web: {image: x, ports: ["8080:80"]}}`} {
		if err := CheckWebPortPublish(c, 0); err != nil {
			t.Errorf("%q with port 0: %v, want nil", c, err)
		}
	}
}

// TC-1091-02: a loopback publish passes.
func TestCheckWebPortPublish_LoopbackPasses(t *testing.T) {
	c := `services: {web: {image: x, ports: ["127.0.0.1:8080:80"]}}`
	if err := CheckWebPortPublish(c, 8080); err != nil {
		t.Errorf("%v, want nil", err)
	}
}

// TC-1091-03, TC-1091-04: a publish on every interface, or on another IPv4
// address, is refused with the rule's own text as a sentence.
func TestCheckWebPortPublish_NotLoopbackRefused(t *testing.T) {
	for _, c := range []struct{ compose, want string }{
		{`services: {web: {image: x, ports: ["8080:80"]}}`, msgEveryInterface},               // TC-1091-03
		{`services: {web: {image: x, ports: ["0.0.0.0:8080:80"]}}`, msgOtherHost("0.0.0.0")}, // TC-1091-04
		{`services: {web: {image: x, ports: ["192.168.1.10:8080:80"]}}`, msgOtherHost("192.168.1.10")},
	} {
		if got := bindRefusal(t, c.compose, CheckWebPortPublish(c.compose, 8080)); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.compose, got, c.want)
		}
	}
}

// TC-1091-05: every service is checked, so a loopback publish in one does not
// excuse an every-interface publish of the same port in another.
func TestCheckWebPortPublish_EveryServiceIsChecked(t *testing.T) {
	c := "services:\n  a: {image: x, ports: [\"127.0.0.1:8080:80\"]}\n  b: {image: y, ports: [\"8080:80\"]}\n"
	if got := bindRefusal(t, c, CheckWebPortPublish(c, 8080)); got != msgEveryInterface {
		t.Errorf("got %q, want %q", got, msgEveryInterface)
	}
}

// TC-1091-06: a compose that publishes other ports only, all readable, is
// told the web port is not published.
func TestCheckWebPortPublish_NotPublished(t *testing.T) {
	c := `services: {web: {image: x, ports: ["127.0.0.1:9000:9000"]}}`
	if got := bindRefusal(t, c, CheckWebPortPublish(c, 8080)); got != msgNotPublished {
		t.Errorf("got %q, want %q", got, msgNotPublished)
	}
}

// TC-1091-07: host networking with no binding for the port passes; a
// binding for it is still judged.
func TestCheckWebPortPublish_HostNetworking(t *testing.T) {
	if err := CheckWebPortPublish(`services: {web: {image: x, network_mode: host}}`, 8080); err != nil {
		t.Errorf("host networking, no ports: %v, want nil", err)
	}
	c := `services: {web: {image: x, network_mode: host, ports: ["0.0.0.0:8080:80"]}}`
	if got := bindRefusal(t, c, CheckWebPortPublish(c, 8080)); got != msgOtherHost("0.0.0.0") {
		t.Errorf("got %q, want %q", got, msgOtherHost("0.0.0.0"))
	}
}

// TC-1091-08: only the declared port is judged; entries the grammar cannot
// read elsewhere in the compose are skipped.
func TestCheckWebPortPublish_OnlyTheWebPortIsJudged(t *testing.T) {
	c := "services:\n" +
		"  web: {image: x, ports: [\"127.0.0.1:8080:80\", \"53:53/udp\"]}\n" +
		"  other: {image: y, ports: [{target: 9000, published: 9000}]}\n"
	if err := CheckWebPortPublish(c, 8080); err != nil {
		t.Errorf("%v, want nil", err)
	}
}

// TC-1091-09: a compose that is not YAML, or not a compose's shape, fails
// closed.
func TestCheckWebPortPublish_UnreadableComposeRefused(t *testing.T) {
	for _, c := range []string{
		"services: [",
		"services: [web]",
		`services: {web: {ports: "8080:80"}}`,
	} {
		err := CheckWebPortPublish(c, 8080)
		if !errors.Is(err, ErrComposeUnreadable) {
			t.Errorf("%q: err = %v, want ErrComposeUnreadable", c, err)
		}
	}
}

// TC-1091-10: the port published only in a form the grammar cannot read gets
// its own text, never the plain "not published" one (F-1091-01).
func TestCheckWebPortPublish_UncheckableForm(t *testing.T) {
	for _, c := range []string{
		`services: {web: {image: x, ports: ["127.0.0.1:8080:80/tcp"]}}`,
		`services: {web: {image: x, ports: [{target: 80, published: 8080, host_ip: 127.0.0.1}]}}`,
	} {
		got := bindRefusal(t, c, CheckWebPortPublish(c, 8080))
		if got == msgNotPublished {
			t.Errorf("%q: got the not-published text", c)
		}
		if got != msgUncheckable {
			t.Errorf("%q:\n got %q\nwant %q", c, got, msgUncheckable)
		}
	}
	// A skipped entry does not hide a readable publish of the port: that
	// publish is judged and gets the rule's own text.
	c := `services: {web: {image: x, ports: ["8080:80", "53:53/udp"]}}`
	if got := bindRefusal(t, c, CheckWebPortPublish(c, 8080)); got != msgEveryInterface {
		t.Errorf("%q:\n got %q\nwant %q", c, got, msgEveryInterface)
	}
}
