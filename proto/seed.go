package proto

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The node enrollment seed: ONE renderer (methodology §5.6, §7 4.2).
//
// A seed is the file that tells a blank node who it is and where its cluster
// is. It has had four renderers — buildrootSeed and openwrtSeed in
// rasputin-provision, renderNodeSeed and renderFirewallSeed in the UI — each
// writing the same keys in the same order, each with its own idea of which
// values needed quoting, and each able to drift from the two images that parse
// them. Four renderers is four chances to mint a seed that a node cannot read,
// and the failure mode is a node that boots, half-joins and says nothing.
//
// So: one Render here, in proto, where both the api and the provisioning CLI
// can reach it, and one Parse beside it so the thing that reads a seed and the
// thing that writes one cannot disagree about the format.
//
// WHAT RENDER GUARANTEES
//
//  1. Every value is single-quoted, with an embedded single quote written as
//     '\''. Both images consume a seed by SOURCING it with sh, so an unquoted
//     value containing a space, a $, a backtick or a semicolon is not data —
//     it is script. Single quotes are the one form sh interprets nothing
//     inside. (Sourcing a file the operator carried on a USB stick is itself a
//     thing being fixed, by `rasputin-agent seed check`; quoting is what makes
//     the file safe to read at all, and it is what a fielded image already
//     handles, because sourcing has always been how both images read it.)
//  2. A value that cannot be written as one shell word — one holding a
//     newline, a carriage return or a NUL — is an error, not something
//     escaped into a shape whose meaning depends on the reader.
//  3. Required fields are required: a seed with no role or no node id is
//     refused here rather than written out for firstboot to reject on a
//     headless box.
//
// WHAT IT DOES NOT DO
//
// It does not judge whether an SSH key is a plausible SSH key, or whether a
// pin is a plausible pin. Those are the callers' rules — setup.ValidOperatorSSHKey
// for the key — because they carry the operator-facing message and proto
// carries no policy. Render's contract is narrower and absolute: whatever it
// is handed, either it comes back out of a POSIX shell byte for byte, or
// rendering fails.

// Seed is one node's enrollment file, before it is rendered.
type Seed struct {
	// Role and NodeID are required. The join token is bound to the node id,
	// and the bus refuses a token presented under any other one.
	Role   NodeRole
	NodeID string
	// ClusterID is the cluster's name (ADR-0003); "" renders the default,
	// the same fallback both images apply.
	ClusterID string
	// NATSURL is the bus the node dials. "" omits the line, leaving the
	// image's own default.
	NATSURL string
	// JoinToken is the bus join credential. Empty for a controlplane, whose
	// api mints its agent's token at start.
	JoinToken string
	// BusPin is the controlplane bus key's pin (BusPinPrefix + base64).
	// Empty omits the line, and the node dials plaintext until the control
	// plane delivers one.
	BusPin string
	// SSHAuthorizedKey is the operator's public key. Empty omits the line:
	// no key is a valid choice, and means a console/UI-only node.
	SSHAuthorizedKey string
	// BusAuth and BusKey belong to a controlplane seed alone: the enforce
	// setting a pre-paired cluster ships with, and the bus PRIVATE key that
	// firstboot moves off the card. Empty omits the line.
	BusAuth string
	BusKey  string
	// Extra is every other KEY=VALUE line, rendered after the known fields in
	// sorted order. Both images read keys this struct does not name —
	// RASPUTIN_NTP_SERVER, RASPUTIN_BMC_HOST, RASPUTIN_FALLBACK_ADDRESS — and
	// a seed from a newer control plane may carry more. Carrying them through
	// rather than naming them all is what lets `rasputin-agent seed check`
	// normalise a seed without silently dropping a field its own build has
	// never heard of.
	Extra map[string]string
	// Origin names what generated this seed, for the header comment. "" is
	// rendered as a generic line rather than a lie.
	Origin string
}

// Seed environment variable names. One place, so the renderer, the parser and
// both images' documentation cannot drift.
const (
	SeedKeyRole      = "RASPUTIN_NODE_ROLE"
	SeedKeyNodeID    = "RASPUTIN_NODE_ID"
	SeedKeyClusterID = "RASPUTIN_CLUSTER_ID"
	SeedKeyNATSURL   = "RASPUTIN_NATS_URL"
	SeedKeyJoinToken = "RASPUTIN_CP_JOIN_TOKEN"
	SeedKeyBusPin    = "RASPUTIN_BUS_PIN"
	SeedKeySSHKey    = "RASPUTIN_SSH_AUTHORIZED_KEY"
	SeedKeyBusAuth   = "RASPUTIN_BUS_AUTH"
	SeedKeyBusKey    = "RASPUTIN_BUS_KEY"
)

// DefaultClusterID is the cluster name a seed with none falls back to. It is
// the value both images already default to, so a dev-box seed rendered here is
// byte-identical to what a default cluster produces (ADR-0003).
const DefaultClusterID = "rasputin"

// SeedFileNameOS and SeedFileNameFirewall are the names each image looks for:
// the OS reads rasputin-seed.env off the RASPUTIN-OS FAT, the firewall reads
// /etc/rasputin/seed.env (and seed.env off the RASPUTIN-FW FAT).
const (
	SeedFileNameOS       = "rasputin-seed.env"
	SeedFileNameFirewall = "seed.env"
)

// DefaultNATSURL is the bus a seed names when the cluster has no hostname of
// its own — a dev box, where the control plane answers to the pre-ADR-0003
// default. Agents resolve it by mDNS, so a seed never carries an IP.
const DefaultNATSURL = "nats://rasputin.local:4222"

// NATSURLFor turns the cluster's mDNS hostname ("<cluster-id>.local",
// SetupState.ClusterHostname) into the bus URL a seed carries, falling back to
// DefaultNATSURL when there is none.
//
// One rule, because getting it wrong is silent: a seed pointing at a host that
// does not exist produces a node that boots, resolves nothing and never joins,
// with nothing in the UI, the seed or the node's logs naming the cause
// (control-plane #70).
func NATSURLFor(clusterHostname string) string {
	h := strings.TrimSpace(clusterHostname)
	if h == "" {
		return DefaultNATSURL
	}
	return "nats://" + h + ":4222"
}

// SeedFileName is the file name a node of this role expects.
func SeedFileName(role NodeRole) string {
	if role == RoleFirewall {
		return SeedFileNameFirewall
	}
	return SeedFileNameOS
}

// RenderSeed writes s as the enrollment file both images source.
//
// The key order is fixed, and it is the order the four renderers this replaces
// already used, so a regenerated seed differs from an old one only in quoting.
func RenderSeed(s Seed) (string, error) {
	if strings.TrimSpace(string(s.Role)) == "" {
		return "", fmt.Errorf("proto: seed needs a role (%s): a node with no role is un-provisioned and firstboot refuses it", SeedKeyRole)
	}
	if !ValidRole(s.Role) {
		return "", fmt.Errorf("proto: seed role %q is not one of %s", s.Role, rolesList())
	}
	if !ValidSeedNodeID(s.NodeID) {
		return "", fmt.Errorf("proto: seed needs a valid node id (%s): %s", SeedKeyNodeID, SeedNodeIDRule)
	}
	clusterID := s.ClusterID
	if strings.TrimSpace(clusterID) == "" {
		clusterID = DefaultClusterID
	}

	var b strings.Builder
	origin := strings.TrimSpace(s.Origin)
	if origin == "" {
		b.WriteString(fmt.Sprintf("# %s — Rasputin node enrollment file\n", SeedFileName(s.Role)))
	} else {
		b.WriteString(fmt.Sprintf("# %s — Rasputin node enrollment file, generated by %s\n", SeedFileName(s.Role), origin))
	}

	// Ordered, and every value quoted — including the ones whose alphabet
	// happens to be safe today. "This one needs no quotes" is a judgement
	// that has to be re-made every time a field's alphabet changes, and the
	// seed is read by a shell running as root on a box nobody is watching.
	lines := []struct {
		key, value string
		// required lines are written even when empty; the rest are omitted,
		// because an absent key and an empty one mean different things to
		// both images.
		required bool
	}{
		{SeedKeyRole, string(s.Role), true},
		{SeedKeyNodeID, s.NodeID, true},
		{SeedKeyClusterID, clusterID, true},
		{SeedKeyNATSURL, s.NATSURL, false},
		{SeedKeyJoinToken, s.JoinToken, false},
		{SeedKeyBusPin, s.BusPin, false},
		{SeedKeySSHKey, s.SSHAuthorizedKey, false},
		{SeedKeyBusAuth, s.BusAuth, false},
		{SeedKeyBusKey, s.BusKey, false},
	}
	for _, k := range sortedKeys(s.Extra) {
		if !validEnvName(k) {
			return "", fmt.Errorf("proto: seed: %q is not a usable variable name", k)
		}
		if _, named := knownSeedKeys[k]; named {
			return "", fmt.Errorf("proto: seed: %s is a named field and must not also be in Extra", k)
		}
		lines = append(lines, struct {
			key, value string
			required   bool
		}{k, s.Extra[k], true})
	}
	for _, l := range lines {
		if l.value == "" && !l.required {
			continue
		}
		q, err := shellQuote(l.value)
		if err != nil {
			return "", fmt.Errorf("proto: seed %s: %w", l.key, err)
		}
		b.WriteString(l.key)
		b.WriteString("=")
		b.WriteString(q)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// knownSeedKeys is every key Seed names as a field, so Extra cannot carry a
// second, contradicting copy of one.
var knownSeedKeys = map[string]struct{}{
	SeedKeyRole: {}, SeedKeyNodeID: {}, SeedKeyClusterID: {}, SeedKeyNATSURL: {},
	SeedKeyJoinToken: {}, SeedKeyBusPin: {}, SeedKeySSHKey: {}, SeedKeyBusAuth: {}, SeedKeyBusKey: {},
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// shellQuote renders v as exactly one POSIX shell word. Single quotes, with
// an embedded single quote closed, escaped and reopened — the '\” idiom.
// Nothing inside single quotes is interpreted by sh, so this is total for
// every byte except the three that cannot appear in a single-line env file.
func shellQuote(v string) (string, error) {
	if i := strings.IndexAny(v, "\n\r\x00"); i >= 0 {
		what := map[byte]string{'\n': "a newline", '\r': "a carriage return", 0: "a NUL"}[v[i]]
		return "", fmt.Errorf("the value contains %s, which cannot be written as one line of an env file", what)
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'", nil
}

// SeedNodeIDRule is the node-id rule in words, for an error an operator reads.
const SeedNodeIDRule = "lowercase letters, digits and hyphens only, at most 63 characters, not starting or ending with a hyphen"

// ValidSeedNodeID reports whether id is a lowercase RFC 1123 DNS label — the
// node's mDNS hostname, the username it presents to the bus, and one token of
// every bus subject scoped to it.
//
// It mirrors busauth.ValidNodeID (tileschema.ValidDNSLabel) rather than
// importing it: proto has no dependencies, by design, and it is the module
// both the api and the provisioning CLI already share. The api module keeps a
// test that the two agree, so a change to either is a failing build and not a
// seed the bus refuses.
func ValidSeedNodeID(id string) bool {
	if len(id) == 0 || len(id) > 63 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(id)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func rolesList() string {
	names := make([]string, 0, len(AllRoles))
	for _, r := range AllRoles {
		names = append(names, string(r))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ParseSeed reads a rendered seed back.
//
// It is deliberately NOT a shell: it reads KEY=VALUE lines, strips one layer
// of single or double quoting, and refuses anything else. That is the whole
// point — a seed arrives on a USB stick, and the thing that decides what it
// means should not be an interpreter that can also run commands. Unknown keys
// are kept in Extra so a seed from a newer control plane is not silently
// truncated by an older reader.
//
// It accepts the unquoted form too, because every seed minted before this
// change is unquoted, and those files are still on the FAT volumes of nodes
// that have not been reflashed.
func ParseSeed(r io.Reader) (Seed, error) {
	var s Seed
	extra := map[string]string{}
	sc := bufio.NewScanner(r)
	// A seed line is short; the default 64 KiB token limit is already far
	// more than any field, and a file that exceeds it is not a seed.
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			return Seed{}, fmt.Errorf("proto: seed line %d is not KEY=VALUE: %q", line, trimmed)
		}
		key = strings.TrimSpace(key)
		if !validEnvName(key) {
			return Seed{}, fmt.Errorf("proto: seed line %d: %q is not a usable variable name", line, key)
		}
		value, err := unquote(value)
		if err != nil {
			return Seed{}, fmt.Errorf("proto: seed line %d (%s): %w", line, key, err)
		}
		switch key {
		case SeedKeyRole:
			s.Role = NodeRole(value)
		case SeedKeyNodeID:
			s.NodeID = value
		case SeedKeyClusterID:
			s.ClusterID = value
		case SeedKeyNATSURL:
			s.NATSURL = value
		case SeedKeyJoinToken:
			s.JoinToken = value
		case SeedKeyBusPin:
			s.BusPin = value
		case SeedKeySSHKey:
			s.SSHAuthorizedKey = value
		case SeedKeyBusAuth:
			s.BusAuth = value
		case SeedKeyBusKey:
			s.BusKey = value
		default:
			extra[key] = value
		}
	}
	if err := sc.Err(); err != nil {
		return Seed{}, fmt.Errorf("proto: read seed: %w", err)
	}
	if len(extra) > 0 {
		s.Extra = extra
	}
	return s, nil
}

// unquote strips one layer of quoting from a seed value.
//
// Single quotes are taken literally, with '\” read as one quote — the exact
// inverse of shellQuote. Double quotes are accepted for the seeds written
// before this change, with the four escapes sh honours inside them; a value
// that would need sh to EXPAND something ($, a backtick, an unescaped
// backslash) is refused rather than guessed at, because guessing is how a
// parser and a shell come to disagree about what a file said.
func unquote(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return "", nil
	case strings.HasPrefix(v, "'"):
		if !strings.HasSuffix(v, "'") || len(v) < 2 {
			return "", fmt.Errorf("the value opens with a single quote and does not close")
		}
		body := v[1 : len(v)-1]
		// Rejoin the '\'' idiom, and refuse a bare quote in the middle,
		// which single quoting cannot produce.
		var out strings.Builder
		for body != "" {
			i := strings.Index(body, "'")
			if i < 0 {
				out.WriteString(body)
				break
			}
			out.WriteString(body[:i])
			rest := body[i:]
			if !strings.HasPrefix(rest, `'\''`) {
				return "", fmt.Errorf("the value has an unescaped single quote inside single quotes")
			}
			out.WriteString("'")
			body = rest[len(`'\''`):]
		}
		return out.String(), nil
	case strings.HasPrefix(v, `"`):
		if !strings.HasSuffix(v, `"`) || len(v) < 2 {
			return "", fmt.Errorf("the value opens with a double quote and does not close")
		}
		body := v[1 : len(v)-1]
		var out strings.Builder
		for i := 0; i < len(body); i++ {
			c := body[i]
			switch c {
			case '\\':
				if i+1 >= len(body) {
					return "", fmt.Errorf("the value ends in a backslash inside double quotes")
				}
				i++
				switch body[i] {
				case '"', '\\', '$', '`':
					out.WriteByte(body[i])
				default:
					return "", fmt.Errorf("the value contains the escape \\%c, which sh does not honour inside double quotes", body[i])
				}
			case '$', '`':
				return "", fmt.Errorf("the value contains %q inside double quotes, which a shell would expand — re-mint the seed", string(c))
			case '"':
				return "", fmt.Errorf("the value has an unescaped double quote inside double quotes")
			default:
				out.WriteByte(c)
			}
		}
		return out.String(), nil
	default:
		// Unquoted: every seed minted before this change. Refuse anything a
		// shell would not have read literally, rather than accept a value
		// whose meaning depended on the reader.
		if i := strings.IndexAny(v, "$`\\\"'"); i >= 0 {
			return "", fmt.Errorf("the value is unquoted and contains %q, which a shell would not read literally", string(v[i]))
		}
		return v, nil
	}
}

// validEnvName reports whether k can be an environment variable name: a
// letter or underscore, then letters, digits or underscores.
func validEnvName(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
