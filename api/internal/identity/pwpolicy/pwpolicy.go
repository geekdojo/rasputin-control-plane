// Package pwpolicy checks a password against the realm's password policy
// before the api hands it to the identity service
// (geekdojo/geekdojo-brain#992, Identity 4.10). Our Keycloak build's Admin
// API answers a policy refusal at reset-password with a 500, the same status
// as a fault (capability rows T170 and T202): keycloak-build.conf's
// features-disabled names admin, so no admin theme exists and building the
// 400's message fails (finding F-1145-41, geekdojo/geekdojo-brain#1145). The
// administrator's reset therefore checks first and shows the rule's sentence.
//
// It mirrors Keycloak's own rules for the policy flows.PasswordPolicy
// names, parsed from that one string: length and maxLength count UTF-16
// units, notUsername and notEmail compare case-insensitively, and the deny
// list matches the password lowercased. A policy term it does not implement
// is refused at New, so the policy can never name a rule this skips.
//
// Nothing here logs. The password arrives as a secret.Value and is never
// copied into a string.
package pwpolicy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Refusal is a rule the password breaks: its sentence, which a person
// reads, and the rule's name. The zero Refusal is no refusal.
type Refusal struct {
	Rule, Sentence string
}

// Refused reports whether r names a rule.
func (r Refusal) Refused() bool { return r.Rule != "" }

// The sentences, as the login theme words them (messages_en.properties).
const (
	sentenceMinLength = "Use at least %d characters."
	sentenceMaxLength = "Use at most %d characters."
	sentenceUsername  = "Don't use your sign-in name as your password."
	sentenceEmail     = "Don't use your email as your password."
	sentenceListed    = "That password is too common. Choose another."
)

// ErrListUnreadable is a deny list that could not be read: the check could
// not finish, so the caller refuses (ERR-CLOSED).
var ErrListUnreadable = errors.New("pwpolicy: the password deny list could not be read")

// Checker is the policy, parsed.
type Checker struct {
	min, max        int
	username, email bool
	listPath        string
}

var term = regexp.MustCompile(`^([A-Za-z]+)\(([^()]*)\)$`)

// New parses policy (flows.PasswordPolicy) and reads deny lists from
// listDir/<the name the policy gives>. It refuses a term it does not
// implement, and does no I/O.
func New(listDir, policy string) (*Checker, error) {
	c := &Checker{}
	for _, t := range strings.Split(policy, " and ") {
		m := term.FindStringSubmatch(strings.TrimSpace(t))
		if m == nil {
			return nil, fmt.Errorf("pwpolicy: the policy term %q does not parse", t)
		}
		name, arg := m[1], m[2]
		switch name {
		case "length", "maxLength":
			n, err := strconv.Atoi(arg)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("pwpolicy: %s(%s) is not a positive number", name, arg)
			}
			if name == "length" {
				c.min = n
			} else {
				c.max = n
			}
		case "notUsername":
			c.username = true
		case "notEmail":
			c.email = true
		case "passwordBlacklist":
			if arg == "" || filepath.Base(arg) != arg || listDir == "" {
				return nil, fmt.Errorf("pwpolicy: the deny list %q is not a plain file name in a list directory", arg)
			}
			c.listPath = filepath.Join(listDir, arg)
		default:
			return nil, fmt.Errorf("pwpolicy: the policy names %s, which this check does not implement", name)
		}
	}
	return c, nil
}

// Check returns the first rule pw breaks, in the policy's order, or the
// zero Refusal. An unreadable deny list is an error wrapping
// ErrListUnreadable.
func (c *Checker) Check(pw secret.Value, username, email string) (Refusal, error) {
	b := pw.Reveal()
	n := utf16Len(b)
	switch {
	case c.min > 0 && n < c.min:
		return Refusal{Rule: "length", Sentence: fmt.Sprintf(sentenceMinLength, c.min)}, nil
	case c.max > 0 && n > c.max:
		return Refusal{Rule: "maxLength", Sentence: fmt.Sprintf(sentenceMaxLength, c.max)}, nil
	case c.username && username != "" && bytes.EqualFold(b, []byte(username)):
		return Refusal{Rule: "notUsername", Sentence: sentenceUsername}, nil
	case c.email && email != "" && bytes.EqualFold(b, []byte(email)):
		return Refusal{Rule: "notEmail", Sentence: sentenceEmail}, nil
	}
	if c.listPath == "" {
		return Refusal{}, nil
	}
	listed, err := c.listed(b)
	if err != nil {
		return Refusal{}, err
	}
	if listed {
		return Refusal{Rule: "passwordBlacklist", Sentence: sentenceListed}, nil
	}
	return Refusal{}, nil
}

// listed scans the deny list for pw, lowercased, one entry per line.
func (c *Checker) listed(pw []byte) (bool, error) {
	f, err := os.Open(c.listPath)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrListUnreadable, err)
	}
	defer f.Close()
	lower := bytes.ToLower(pw)
	defer clear(lower)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if bytes.Equal(bytes.ToLower(bytes.TrimRight(sc.Bytes(), "\r")), lower) {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("%w: %v", ErrListUnreadable, err)
	}
	return false, nil
}

// utf16Len is b's length in UTF-16 code units, as Java's String.length
// counts: a character outside the Basic Multilingual Plane counts 2.
func utf16Len(b []byte) int {
	n := 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}
