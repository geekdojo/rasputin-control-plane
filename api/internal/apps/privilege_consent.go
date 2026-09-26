package apps

import (
	"errors"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// Server-enforced consent on a catalog upgrade that raises the app's privilege
// tier (auth-methodology §9 dec 12, Bryce 2026-09-26; geekdojo/geekdojo-brain#522).
//
// An upgrade that moves an app UP the tier ladder — routine < elevated <
// host-trusting, compared by tileschema.TierRank and never by string — is
// refused unless the owner consented to it, and the consent is recorded on the
// app as a PrivilegeAck {at, by, what}. An upgrade that keeps or lowers the
// tier needs nothing.
//
// Scope, as decided:
//
//   - First install is unchanged. The UI shows the tier and the server
//     enforces nothing (the 2026-09-12 ruling "no privilege re-consent at the
//     API" stands for installs). Install records the tier, so the first
//     upgrade has something to compare against.
//   - Custom compose stays open (ADR-0006 D12): it has no tile and no tier.
//   - New grants inside an unchanged tier do NOT count as a raise. Only the
//     rank going up does.
//   - A re-apply ({"sha256"}) returns to the compose the app last ran, with
//     the tier that ran with it; it is not a catalog upgrade and is not gated.

// ErrPrivilegeConsentRequired is a tier-raising upgrade with no consent that
// covers it. The HTTP layer answers it with a 409; the saga fails the job with
// it. The wrapped text is written for the owner.
var ErrPrivilegeConsentRequired = errors.New("privilege consent required")

// PrivilegeChange is what an upgrade does to an app's privilege tier.
type PrivilegeChange struct {
	// FromTier is the tier recorded for the installed compose; "" when none
	// was recorded, which counts as routine.
	FromTier string
	// Privilege is the target tile's declaration, with Tier resolved so it is
	// never "".
	Privilege tileschema.Privilege
	// Raises is the whole question: does the tier's rank go up?
	Raises bool
}

// UpgradePrivilege compares the app's recorded tier with the tier target
// declares.
func UpgradePrivilege(app *App, target tileschema.Tile) PrivilegeChange {
	p := target.DeclaredPrivilege()
	p.Tier = p.EffectiveTier()
	return PrivilegeChange{
		FromTier:  app.PrivilegeTier,
		Privilege: p,
		Raises:    tileschema.TierRaised(app.PrivilegeTier, p.Tier),
	}
}

// Consent is the record of accepting this change for target.
func (c PrivilegeChange) Consent(target UpgradeTarget) PrivilegeConsent {
	return PrivilegeConsent{
		FromTier:       c.FromTier,
		Tier:           c.Privilege.Tier,
		DockerSocket:   c.Privilege.DockerSocket,
		Grants:         append([]string(nil), c.Privilege.Grants...),
		CatalogVersion: target.CatalogVersion,
		ComposeSHA256:  ComposeHash(target.Tile.ComposeYAML),
	}
}

// Refusal is the owner-facing reason a raise without consent is refused:
// what is being raised, and what consent the request needs to carry.
func (c PrivilegeChange) Refusal() string {
	from := strings.ToUpper(tileschema.Privilege{Tier: c.FromTier}.EffectiveTier())
	if c.FromTier == "" {
		from += " (no tier was recorded for the installed version, so it counts as routine)"
	}
	to := strings.ToUpper(c.Privilege.Tier)
	var b strings.Builder
	fmt.Fprintf(&b, "this upgrade raises the app's privilege from %s to %s", from, to)
	if c.Privilege.DockerSocket {
		b.WriteString(", including control of the container runtime socket")
	}
	if len(c.Privilege.Grants) > 0 {
		fmt.Fprintf(&b, " (it takes: %s)", strings.Join(c.Privilege.Grants, ", "))
	}
	fmt.Fprintf(&b, `, and it needs your consent: send the upgrade again with "acceptPrivilegeTier": %q`, c.Privilege.Tier)
	return b.String()
}

// CheckUpgradeConsent is the saga's gate: nil when the upgrade to target does
// not raise the app's tier, or when the app's recorded consent is for exactly
// target's compose at a tier that covers it. Otherwise
// ErrPrivilegeConsentRequired, saying what is raised and what is needed.
func CheckUpgradeConsent(app *App, target UpgradeTarget) error {
	change := UpgradePrivilege(app, target.Tile)
	if !change.Raises {
		return nil
	}
	if ack := app.PrivilegeAck; ack != nil &&
		ack.What.ComposeSHA256 == ComposeHash(target.Tile.ComposeYAML) &&
		tileschema.TierCovers(ack.What.Tier, change.Privilege.Tier) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrPrivilegeConsentRequired, change.Refusal())
}
