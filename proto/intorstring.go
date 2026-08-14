package proto

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// IntOrString is a knob that may be an absolute count or a percentage of the
// thing it applies to: `4` or `"20%"`.
//
// It is deliberately the shape operators already know from Kubernetes
// `maxUnavailable`, because the alternative — two fields, or a magic
// "values under 1 are fractions" rule — is a thing every reader has to learn
// once and misremember afterwards. The familiar analogue for a *failure*
// budget specifically is Ansible's `max_fail_percentage`.
//
// Why a fleet knob needs to be size-relative at all: an absolute 4 is ~18% of
// a 22-node compute tier and 100% of a 2-node one, so a flat default makes
// "bounded" fan-out a single unbounded batch on a small cluster. Same argument
// for a failure budget — Bryce, 2026-08-11: "3 is fine for 24 nodes, useless on
// a 3-node cluster." ADR-0005 Decisions 6 + 7.
type IntOrString struct {
	// Value is the absolute count, or the percentage numerator when Percent.
	Value int
	// Percent reports whether Value is a percentage of the population rather
	// than a count of nodes.
	Percent bool
}

// Int returns an absolute IntOrString.
func Int(v int) IntOrString { return IntOrString{Value: v} }

// Percent returns a percentage IntOrString.
func Percent(v int) IntOrString { return IntOrString{Value: v, Percent: true} }

// Resolve converts the knob to an absolute count against a population.
//
// A percentage rounds DOWN and is NOT floored at 1 here: the floor is the
// caller's, because the two users of this type disagree about what zero means.
// A max-in-flight of zero is nonsense and gets clamped up; a failure budget of
// zero means "unlimited" and must survive.
func (v IntOrString) Resolve(total int) int {
	if !v.Percent {
		return v.Value
	}
	if total <= 0 {
		return 0
	}
	return v.Value * total / 100
}

func (v IntOrString) String() string {
	if v.Percent {
		return strconv.Itoa(v.Value) + "%"
	}
	return strconv.Itoa(v.Value)
}

// Validate rejects values that cannot mean anything. Negative is nonsense in
// both forms; over 100% is a percentage that has lost track of what it is a
// percentage of, and is far likelier a typo than an intent.
func (v IntOrString) Validate() error {
	if v.Value < 0 {
		return fmt.Errorf("%s: must not be negative", v)
	}
	if v.Percent && v.Value > 100 {
		return fmt.Errorf("%s: must not exceed 100%%", v)
	}
	return nil
}

func (v IntOrString) MarshalJSON() ([]byte, error) {
	if v.Percent {
		return json.Marshal(v.String())
	}
	return json.Marshal(v.Value)
}

// UnmarshalJSON accepts `4`, `"4"` and `"20%"`. The quoted-integer form is
// accepted rather than rejected because it is what a form field or a shell
// pipeline produces, and refusing it would be pedantry with no safety payoff.
func (v *IntOrString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] != '"' {
		var n int
		if err := json.Unmarshal(b, &n); err != nil {
			return fmt.Errorf("expected a number or a %q string: %w", "N%", err)
		}
		*v = IntOrString{Value: n}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	percent := strings.HasSuffix(s, "%")
	n, err := strconv.Atoi(strings.TrimSuffix(s, "%"))
	if err != nil {
		return fmt.Errorf("%q is not a number or a percentage", s)
	}
	*v = IntOrString{Value: n, Percent: percent}
	return nil
}
