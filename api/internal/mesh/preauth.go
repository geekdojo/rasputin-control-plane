package mesh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Headscale pre-auth keys are minted in exactly one place, MintPreAuthKey,
// under one of two profiles. The profile, not the caller, decides the tags,
// the reuse flags and the expiry bound, so no request can mint a key that
// admits a device as something it is not.
//
//   - PreAuthNode is the enrolment key for a Rasputin node. It carries
//     meshNodeTag, is single-use and non-ephemeral, and is minted inside the
//     enrol dispatch step, which expires it explicitly when the step ends.
//     nodeEnrolKeyExpiry is only a safety net for an api that dies mid-step.
//   - PreAuthUserDevice is a key an operator creates for a laptop or phone.
//     Its tag set is fixed to UserDeviceTag, no tag:rasputin-* tag is ever
//     accepted, and its expiry is capped at UserDeviceKeyMaxExpiry.

// PreAuthProfile selects which admission profile a key is minted under.
type PreAuthProfile int

const (
	// PreAuthNode mints the enrolment key for a Rasputin node.
	PreAuthNode PreAuthProfile = iota + 1
	// PreAuthUserDevice mints an operator-requested key for a user device.
	PreAuthUserDevice
)

func (p PreAuthProfile) String() string {
	switch p {
	case PreAuthNode:
		return "node"
	case PreAuthUserDevice:
		return "user-device"
	}
	return fmt.Sprintf("PreAuthProfile(%d)", int(p))
}

const (
	// UserDeviceTag is the only tag a user-device key may carry.
	UserDeviceTag = "tag:user-device"

	// reservedTagPrefix names the tags only the control plane may assign.
	// meshNodeTag is one of them, and it is what reconcile reads as "this
	// device is a Rasputin node".
	reservedTagPrefix = "tag:rasputin-"

	// UserDeviceKeyDefaultExpiry applies when a request names no expiry.
	UserDeviceKeyDefaultExpiry = 24 * time.Hour

	// UserDeviceKeyMaxExpiry caps a user-device key's lifetime. Headscale is
	// the only thing that checks the key, so its expiry is the only bound on
	// a key that is copied off the page and never used. It matches the
	// longest choice the Keys page offers.
	UserDeviceKeyMaxExpiry = 7 * 24 * time.Hour

	// nodeEnrolKeyExpiry is the safety net on a node enrolment key. The key's
	// real end is the enrol dispatch step ending: the step expires it on
	// success and failure alike. This bound only covers an api that stops
	// mid-step and never gets to expire it.
	nodeEnrolKeyExpiry = 10 * time.Minute
)

// ErrPreAuthRequest is wrapped by every refusal of a request's own fields,
// so an HTTP handler can answer 400 rather than 500.
var ErrPreAuthRequest = errors.New("pre-auth key request refused")

// PreAuthKeyRequest carries what a caller may choose about a key. Which of
// the fields are honoured depends on the profile: PreAuthNode ignores none
// of them silently — it refuses any that is set.
type PreAuthKeyRequest struct {
	Reusable  bool
	Ephemeral bool
	// ExpiresIn is the requested lifetime. Zero means the profile default.
	ExpiresIn time.Duration
	// Tags must be empty or exactly [UserDeviceTag] for a user-device key.
	Tags []string
}

// MintedPreAuthKey is a freshly minted key. Value is the plaintext, which
// Headscale returns only at creation.
type MintedPreAuthKey struct {
	ID      string
	Value   string
	User    string
	Tags    []string
	Expires time.Time
}

// ResolvePreAuthKey checks req against profile and returns the exact
// Headscale input the key would be minted with. It never talks to
// Headscale, so a handler can validate a request before touching anything.
func ResolvePreAuthKey(profile PreAuthProfile, user string, req PreAuthKeyRequest, now time.Time) (CreatePreAuthKeyInput, error) {
	if user == "" {
		return CreatePreAuthKeyInput{}, errors.New("mesh: pre-auth key needs a Headscale user")
	}
	switch profile {
	case PreAuthNode:
		if req.Reusable || req.Ephemeral || req.ExpiresIn != 0 || len(req.Tags) > 0 {
			return CreatePreAuthKeyInput{}, fmt.Errorf("%w: a node enrolment key's tags, reuse and expiry are fixed", ErrPreAuthRequest)
		}
		return CreatePreAuthKeyInput{
			User:   user,
			Expiry: now.Add(nodeEnrolKeyExpiry),
			Tags:   []string{meshNodeTag},
		}, nil
	case PreAuthUserDevice:
		for _, t := range req.Tags {
			if strings.HasPrefix(t, reservedTagPrefix) {
				return CreatePreAuthKeyInput{}, fmt.Errorf("%w: tag %q is reserved for Rasputin nodes", ErrPreAuthRequest, t)
			}
			if t != UserDeviceTag {
				return CreatePreAuthKeyInput{}, fmt.Errorf("%w: a user-device key is always tagged %s; tag %q is not accepted", ErrPreAuthRequest, UserDeviceTag, t)
			}
		}
		expiresIn := req.ExpiresIn
		if expiresIn == 0 {
			expiresIn = UserDeviceKeyDefaultExpiry
		}
		if expiresIn < 0 {
			return CreatePreAuthKeyInput{}, fmt.Errorf("%w: expiry must be positive", ErrPreAuthRequest)
		}
		if expiresIn > UserDeviceKeyMaxExpiry {
			return CreatePreAuthKeyInput{}, fmt.Errorf("%w: expiry %s exceeds the %s maximum for a user-device key", ErrPreAuthRequest, expiresIn, UserDeviceKeyMaxExpiry)
		}
		return CreatePreAuthKeyInput{
			User:      user,
			Reusable:  req.Reusable,
			Ephemeral: req.Ephemeral,
			Expiry:    now.Add(expiresIn),
			Tags:      []string{UserDeviceTag},
		}, nil
	}
	return CreatePreAuthKeyInput{}, fmt.Errorf("mesh: unknown pre-auth profile %v", profile)
}

// MintPreAuthKey is the one place a Headscale pre-auth key is created. The
// key is minted for the service's default Headscale user.
func (s *Service) MintPreAuthKey(ctx context.Context, profile PreAuthProfile, req PreAuthKeyRequest) (*MintedPreAuthKey, error) {
	in, err := ResolvePreAuthKey(profile, s.cfg.DefaultUser, req, time.Now())
	if err != nil {
		return nil, err
	}
	id, value, err := s.Client().CreatePreAuthKey(ctx, in)
	if err != nil {
		return nil, err
	}
	if id == "" || value == "" {
		return nil, errors.New("mesh: headscale returned a pre-auth key with no id or value")
	}
	return &MintedPreAuthKey{
		ID:      id,
		Value:   value,
		User:    in.User,
		Tags:    slices.Clone(in.Tags),
		Expires: in.Expiry,
	}, nil
}

// ParseUserDeviceKeyExpiry reads a request's expiry string. Empty means the
// default; anything that is not a positive Go duration is refused rather
// than replaced with a default, so the key never outlives what was asked.
func ParseUserDeviceKeyExpiry(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%w: expiresIn %q is not a duration like \"24h\"", ErrPreAuthRequest, s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%w: expiry must be positive", ErrPreAuthRequest)
	}
	return d, nil
}
