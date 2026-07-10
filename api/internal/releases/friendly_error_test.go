package releases

import (
	"context"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestFriendlyFetchError(t *testing.T) {
	// The exact shape Go produces for the reported failure: a DNS i/o timeout,
	// wrapped dial → url.Error, carrying the real host + resolver IP.
	dnsTimeout := &url.Error{
		Op:  "Get",
		URL: "https://api.github.com/repos/geekdojo/rasputin-os/releases?per_page=100",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{
			Err: "i/o timeout", Name: "api.github.com", Server: "127.0.0.53:53", IsTimeout: true,
		}},
	}
	noRoute := &url.Error{
		Op:  "Get",
		URL: "https://api.github.com/repos/geekdojo/rasputin-os/releases?per_page=100",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH},
	}

	tests := []struct {
		name    string
		err     error
		wantSub string // message must contain this
	}{
		{"nil", nil, ""},
		{"dns timeout", dnsTimeout, "internet connection"},
		{"no route", noRoute, "Couldn't reach the update server"},
		{"deadline", context.DeadlineExceeded, "Timed out"},
		{"rate limited", &httpError{status: 403, url: "https://api.github.com/x", body: "rate limit exceeded"}, "rate-limiting"},
		{"too many requests", &httpError{status: 429, url: "https://api.github.com/x"}, "rate-limiting"},
		{"server error", &httpError{status: 503, url: "https://api.github.com/x"}, "temporarily unavailable"},
		{"not found", &httpError{status: 404, url: "https://api.github.com/x"}, "release channel"},
	}

	// Nothing the user sees may leak backend identity or network internals.
	forbidden := []string{"api.github.com", "github", "GitHub", "127.0.0.53", "dial tcp", "udp", "resolv"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := friendlyFetchError(tt.err)
			if tt.wantSub == "" {
				if got != "" {
					t.Fatalf("want empty message, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSub) {
				t.Fatalf("message %q does not contain %q", got, tt.wantSub)
			}
			for _, bad := range forbidden {
				if strings.Contains(got, bad) {
					t.Fatalf("message leaks %q: %q", bad, got)
				}
			}
		})
	}
}
