package credmac_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac/credmactest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

var keyedFormat = regexp.MustCompile(`^k1-[0-9a-f]{64}$`)

// TC-827-01: Sum is deterministic and is "k1-" and 64 lowercase hex.
func TestSum_FormatAndDeterminism(t *testing.T) {
	k := credmactest.Key(t)
	a := k.Sum("p", []byte("a"), []byte("b"))
	b := k.Sum("p", []byte("a"), []byte("b"))
	if a != b {
		t.Errorf("two Sums of the same input differ: %s, %s", a, b)
	}
	if !keyedFormat.MatchString(a) {
		t.Errorf("Sum = %q, want k1- and 64 lowercase hex", a)
	}
	// Pinned: computed outside Go as HMAC-SHA256 under credmactest's key over
	// the purpose and each part, each with a big-endian uint64 length prefix.
	const want = "k1-53c93b534ef46563336939f776a1d2c6652ea445e24653353a32482a62f188de"
	state := `{"firewall":{"redirect":[{"dest":"lan","dest_ip":"192.168.1.10","dest_port":"80","name":"web","proto":"tcp","src":"wan","src_dport":"8080","target":"DNAT"}],"rule":[]},"network":{"wan":{"password":"SENTINEL-PPPOE-PASSWORD","proto":"pppoe","service":"internet","username":"user@isp"}}}`
	if got := k.Sum("firewall.state", []byte(state)); got != want {
		t.Errorf("Sum vector = %s, want %s", got, want)
	}
}

// TC-827-02: every input moves the result, including how the bytes are split
// into parts.
func TestSum_Sensitivity(t *testing.T) {
	k := credmactest.Key(t)
	base := k.Sum("p", []byte("ab"), []byte("c"))

	other := credmactest.KeyBytes()
	other[0] ^= 0xff
	k2, err := credmac.New(secret.New(other))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"a different key":             k2.Sum("p", []byte("ab"), []byte("c")),
		"a different purpose":         k.Sum("q", []byte("ab"), []byte("c")),
		"a changed byte in part one":  k.Sum("p", []byte("aB"), []byte("c")),
		"a changed byte in part two":  k.Sum("p", []byte("ab"), []byte("C")),
		"the split (a, bc)":           k.Sum("p", []byte("a"), []byte("bc")),
		"the parts joined into one":   k.Sum("p", []byte("abc")),
		"the purpose moved into part": k.Sum("", []byte("p"), []byte("ab"), []byte("c")),
	} {
		if got == base {
			t.Errorf("%s: Sum did not change", name)
		}
	}
}

// TC-827-03: New refuses an empty and a 31-byte key, and accepts 32 bytes.
func TestNew_RefusesAShortKey(t *testing.T) {
	for _, n := range []int{0, 31} {
		k, err := credmac.New(secret.New(make([]byte, n)))
		if err == nil || k != nil {
			t.Errorf("a %d-byte key: key %v, err %v; want nil and an error", n, k, err)
		}
	}
	if _, err := credmac.New(secret.Value{}); err == nil {
		t.Error("the zero Value was accepted as a key")
	}
	if k, err := credmac.New(secret.New(make([]byte, 32))); err != nil || k == nil {
		t.Errorf("a 32-byte key: key %v, err %v; want a key", k, err)
	}
}

// TC-827-04: IsKeyed is true only for a Sum output.
func TestIsKeyed(t *testing.T) {
	sum := credmactest.Key(t).Sum("p")
	for _, c := range []struct {
		h    string
		want bool
	}{
		{sum, true},
		{"23dba914fbe610d66dedb1e3140395ddd7019e045844650e8a62b275840fa71d", false}, // a legacy firewall hash
		{"d305fd5a1713d3b5", false}, // a legacy BMC hash
		{"", false},
	} {
		if got := credmac.IsKeyed(c.h); got != c.want {
			t.Errorf("IsKeyed(%q) = %v, want %v", c.h, got, c.want)
		}
	}
}

// TC-827-05: a *Key never renders its key bytes, raw or hex, through fmt,
// encoding/json or log/slog.
func TestKey_NeverRenders(t *testing.T) {
	raw := []byte("KEYBYTES-SENTINEL-0123456789abcd") // 32 bytes, printable
	k, err := credmac.New(secret.New(raw))
	if err != nil {
		t.Fatal(err)
	}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		outs = append(outs, fmt.Sprintf(verb, k), fmt.Sprintf(verb, *k))
	}
	if b, err := json.Marshal(k); err == nil {
		outs = append(outs, string(b))
	}
	for _, h := range []func(*bytes.Buffer) slog.Handler{
		func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(h(&buf)).Info("key", "key", k, "deref", *k)
		outs = append(outs, buf.String())
	}
	for _, out := range outs {
		for _, enc := range []string{string(raw), hex.EncodeToString(raw)} {
			if strings.Contains(out, enc) {
				t.Errorf("the key rendered: %q", out)
			}
		}
	}
}
