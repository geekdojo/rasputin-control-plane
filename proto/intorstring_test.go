package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIntOrString_JSONRoundTrip(t *testing.T) {
	cases := []struct {
		in       string
		want     IntOrString
		wantBack string
	}{
		{`4`, Int(4), `4`},
		{`0`, Int(0), `0`},
		// A quoted integer is what a form field or a shell pipeline produces.
		// Accepting it costs nothing; rejecting it is pedantry with no safety
		// payoff. It marshals back in the canonical numeric form.
		{`"4"`, Int(4), `4`},
		{`"20%"`, Percent(20), `"20%"`},
		{`"100%"`, Percent(100), `"100%"`},
		{`" 15% "`, Percent(15), `"15%"`},
	}
	for _, c := range cases {
		var got IntOrString
		if err := json.Unmarshal([]byte(c.in), &got); err != nil {
			t.Errorf("unmarshal %s: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("unmarshal %s = %+v, want %+v", c.in, got, c.want)
		}
		back, err := json.Marshal(got)
		if err != nil {
			t.Errorf("marshal %+v: %v", got, err)
			continue
		}
		if string(back) != c.wantBack {
			t.Errorf("remarshal %s = %s, want %s", c.in, back, c.wantBack)
		}
	}
}

func TestIntOrString_RejectsNonsense(t *testing.T) {
	for _, in := range []string{`"twenty"`, `"20 percent"`, `"%"`, `true`, `[4]`} {
		var v IntOrString
		if err := json.Unmarshal([]byte(in), &v); err == nil {
			t.Errorf("unmarshal %s succeeded as %+v, want an error", in, v)
		}
	}
}

func TestIntOrString_Resolve(t *testing.T) {
	cases := []struct {
		v     IntOrString
		total int
		want  int
	}{
		{Int(4), 22, 4}, // absolute ignores the population
		{Int(4), 2, 4},  // ...including when it exceeds it; clamping is the caller's
		{Percent(20), 20, 4},
		{Percent(15), 22, 3}, // floor(3.3) — the approved 24-node anchor
		{Percent(15), 8, 1},  // floor(1.2)
		{Percent(15), 3, 0},  // floor(0.45) — NOT floored to 1 here, on purpose:
		// a max-in-flight of zero is nonsense and gets clamped up, a failure
		// budget of zero means unlimited and must survive. The two callers
		// disagree, so Resolve stays out of it.
		{Percent(50), 0, 0},
	}
	for _, c := range cases {
		if got := c.v.Resolve(c.total); got != c.want {
			t.Errorf("%s.Resolve(%d) = %d, want %d", c.v, c.total, got, c.want)
		}
	}
}

func TestIntOrString_Validate(t *testing.T) {
	for _, v := range []IntOrString{Int(0), Int(1), Int(1000), Percent(0), Percent(100)} {
		if err := v.Validate(); err != nil {
			t.Errorf("%s: unexpected error %v", v, err)
		}
	}
	for _, v := range []IntOrString{Int(-1), Percent(-5), Percent(101)} {
		if err := v.Validate(); err == nil {
			t.Errorf("%s: want an error, got nil", v)
		} else if !strings.Contains(err.Error(), v.String()) {
			t.Errorf("%s: error %q does not name the offending value", v, err)
		}
	}
}
