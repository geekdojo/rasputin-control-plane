package nameserver

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPublicUpstream is the loop-safe fallback used when the CP's own DHCP
// resolver can't be inherited safely (it points back at us, or none was found).
// It is surfaced in the UI so the operator knows household queries go here until
// they set an explicit upstream — the AA-9 upstream-privacy choice. Cloudflare.
const DefaultPublicUpstream = "1.1.1.1:53"

// Upstream is the resolved forwarding target: Addr ("ip:port") plus whether we
// FellBack to the public default because no inherited upstream was safe (the UI
// surfaces the fallback).
type Upstream struct {
	Addr     string
	FellBack bool
}

// ResolveUpstream picks the effective forwarding upstream (ADR-0004 §10 —
// detect-and-fall-back, decided with Bryce 2026-08-09):
//
//   - a non-empty operator-configured upstream is used verbatim (normalized to
//     :53) and trusted — the runtime self-loop guard still protects it.
//   - otherwise ("auto") the first candidate that is neither self nor loopback
//     is inherited: the CP's DHCP-provided resolver.
//   - if none is safe, fall back to the public default and flag FellBack.
//
// Self is skipped because inheriting our own address loops straight back into
// this responder; loopback is skipped because that is the systemd-resolved stub,
// whose real upstream we can't see here and which — when the operator has pointed
// the LAN's DNS at us — may itself point back at this box.
func ResolveUpstream(configured string, self net.IP, candidates []net.IP) Upstream {
	if c := strings.TrimSpace(configured); c != "" {
		return Upstream{Addr: withDefaultPort(c), FellBack: false}
	}
	for _, ip := range candidates {
		if ip == nil || ip.To4() == nil {
			continue
		}
		if (self != nil && ip.Equal(self)) || ip.IsLoopback() {
			continue
		}
		return Upstream{Addr: net.JoinHostPort(ip.String(), "53"), FellBack: false}
	}
	return Upstream{Addr: DefaultPublicUpstream, FellBack: true}
}

// withDefaultPort appends :53 unless the string already carries a port.
func withDefaultPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// SystemUpstreams gathers the CP's candidate upstream resolvers, best-effort:
// the DNS servers systemd-networkd learned via DHCP (its lease files) first —
// the real upstream, since resolv.conf is the local resolved stub on
// rasputin-os — then any nameservers in resolv.conf. IPv4 only, deduped in
// order. Unreadable sources are skipped, never fatal: ResolveUpstream falls back
// to the public default when nothing usable turns up.
func SystemUpstreams(resolvConf, leaseDir string) []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if ip == nil || ip.To4() == nil || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	if entries, err := os.ReadDir(leaseDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			for _, ip := range leaseDNS(filepath.Join(leaseDir, e.Name())) {
				add(ip)
			}
		}
	}
	for _, ip := range resolvConfNameservers(resolvConf) {
		add(ip)
	}
	return out
}

// leaseDNS parses the DNS= line(s) of a systemd-networkd lease file.
func leaseDNS(path string) []net.IP {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "DNS=")
		if !ok {
			continue
		}
		for _, tok := range strings.Fields(v) {
			if ip := net.ParseIP(tok); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

// resolvConfNameservers parses the `nameserver` lines of a resolv.conf.
func resolvConfNameservers(path string) []net.IP {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}
