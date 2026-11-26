package accounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// The claim kinds (identity-authz.md §3.4): a custom claim an administrator
// defines, its kind and allowed values, and each person's values, which an
// app may authorize on, so nobody edits their own.

// claimName is a claim's name: 2 to 40 lowercase letters, digits or
// underscores.
var claimName = regexp.MustCompile(`^[a-z0-9_]{2,40}$`)

// reservedClaims are the names no claim may take (F-994-07): the JWT
// registered claims (RFC 7519 §4.1, RFC 7800, RFC 8693), the OpenID
// Connect ID token and standard claims (Core §2, §3.1.3.6, §5.1, §5.6.2,
// §7.4; Front- and Back-Channel Logout), the names the identity service
// puts in every token, and the ones that carry access: groups, roles,
// realm_access, resource_access, entitlements (RFC 9068 §7.2.1),
// authorization_details (RFC 9396) and upn (MicroProfile JWT). A name starting rasputin is refused
// too (reservedClaim).
var reservedClaims = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields(`
		iss sub aud exp nbf iat jti cnf act may_act scope client_id
		auth_time nonce acr amr azp at_hash c_hash s_hash sid events sub_jwk _claim_names _claim_sources
		name given_name family_name middle_name nickname preferred_username profile picture website
		email email_verified gender birthdate zoneinfo locale phone_number phone_number_verified address updated_at
		typ session_state
		groups roles realm_access resource_access entitlements authorization_details upn`) {
		m[n] = true
	}
	return m
}()

// reservedClaim reports whether name is a reserved claim name.
func reservedClaim(name string) bool {
	return reservedClaims[name] || strings.HasPrefix(name, "rasputin")
}

// The claim kinds' refusal sentences (ERR-MESSAGE).
const (
	sentenceClaimName     = "A claim name is 2 to 40 lowercase letters, digits or underscores."
	sentenceClaimReserved = "That claim name is reserved for the sign-in service, apps' access or Rasputin itself, so choose another."
	sentenceClaimKind     = "A claim's kind is text, list, boolean or number."
	sentenceClaimAllowed  = "Each allowed value is 1 to 255 characters, with no control characters."
	sentenceClaimNumber   = "Each allowed value of a number claim is a whole number."
	sentenceClaimBoolean  = "A boolean claim is true or false, so it takes no allowed values."
	sentenceClaimClients  = "Rasputin can't send a claim to chosen apps yet, so this claim wasn't defined."
	sentenceClaimHeld     = "Some people hold values this definition wouldn't allow, so the claim wasn't changed. Change or clear their values first."
)

// claimNameRefusal is the refusal of a claim name, nil for a valid one.
func claimNameRefusal(name string) error {
	switch {
	case !claimName.MatchString(name):
		return refusal(StepChange, "claim_name", sentenceClaimName)
	case reservedClaim(name):
		return refusal(StepChange, "claim_reserved", sentenceClaimReserved)
	}
	return nil
}

// claimDef checks a define_claim spec and returns the definition. Every
// chosen client is refused: no tile yet declares the claim names it
// authorizes on, so a claim sent to a chosen app could not be checked
// against them (ERR-CLOSED).
func claimDef(s defSpec) (ClaimDef, error) {
	if err := claimNameRefusal(s.Name); err != nil {
		return ClaimDef{}, err
	}
	if !slices.Contains([]string{ClaimText, ClaimList, ClaimBoolean, ClaimNumber}, s.Kind) {
		return ClaimDef{}, refusal(StepChange, "claim_kind", sentenceClaimKind)
	}
	if len(s.Clients) > 0 {
		return ClaimDef{}, refusal(StepChange, "claim_clients", sentenceClaimClients)
	}
	if s.Kind == ClaimBoolean && len(s.Values) > 0 {
		return ClaimDef{}, refusal(StepChange, "claim_values", sentenceClaimBoolean)
	}
	var values []string
	for _, v := range s.Values {
		if !validText([]byte(v)) {
			return ClaimDef{}, refusal(StepChange, "claim_values", sentenceClaimAllowed)
		}
		if _, err := strconv.ParseInt(v, 10, 64); s.Kind == ClaimNumber && err != nil {
			return ClaimDef{}, refusal(StepChange, "claim_values", sentenceClaimNumber)
		}
		if !slices.Contains(values, v) {
			values = append(values, v)
		}
	}
	return ClaimDef{Name: s.Name, Kind: s.Kind, Values: values}, nil
}

// parseClaimValues decodes set_claims' value: a JSON object from claim
// names to lists of values, each name a valid claim name and each value 1
// to 255 characters with no control character; an empty list removes the
// claim's value. It reports whether b is one.
func parseClaimValues(b []byte) (map[string][]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var m map[string][]string
	if err := dec.Decode(&m); err != nil || dec.More() || len(m) == 0 {
		return nil, false
	}
	for name, vs := range m {
		if vs == nil || !claimName.MatchString(name) || reservedClaim(name) {
			return nil, false
		}
		for _, v := range vs {
			if !validText([]byte(v)) {
				return nil, false
			}
		}
	}
	return m, true
}

// defineClaim writes the claim: its admin-only profile attribute with its
// kind's validators, and its client scope with both mappers.
func (c *Changes) defineClaim(ctx context.Context, _ *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error) {
	d, err := claimDef(spec)
	if err != nil {
		return nil, err
	}
	err = users.DefineClaim(ctx, d)
	switch {
	case errors.Is(err, ErrClaimHeld):
		return nil, refusal(StepChange, "claim_held", sentenceClaimHeld)
	case err != nil:
		return nil, definitionWritten(err)
	}
	return map[string]any{"outcome": outcomeDefined}, nil
}

// deleteClaim removes the claim: its scope, every person's value and its
// profile attribute.
func (c *Changes) deleteClaim(ctx context.Context, _ *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error) {
	if !claimName.MatchString(spec.Name) {
		return nil, refusal(StepChange, "claim_name", sentenceClaimName)
	}
	n, err := users.DeleteClaim(ctx, spec.Name)
	if err != nil {
		return nil, definitionWritten(err)
	}
	return map[string]any{"outcome": outcomeRemoved, "values": n}, nil
}

// setClaims sets the held claim values on the account: each claim named
// must be defined, and a value its validators refuse changes nothing.
func (c *Changes) setClaims(ctx context.Context, sc *jobs.StepCtx, users DefinitionUsers, spec defSpec) (map[string]any, error) {
	v, text, err := c.heldText(sc)
	if err != nil {
		return nil, err
	}
	defer v.Destroy()
	values, ok := parseClaimValues([]byte(text))
	if !ok {
		return nil, failStep(StepChange, sentenceClaimValues, errors.New("the held value is not claim values"))
	}
	defined, err := users.Claims(ctx)
	if err != nil {
		return nil, failStep(StepChange, sentenceCheck, err)
	}
	for name := range values {
		if !slices.Contains(defined, name) {
			return nil, refusal(StepChange, "unknown_claim", sentenceUnknownClaim)
		}
	}
	err = users.SetClaims(ctx, spec.AccountID, values)
	var ie *idclient.Error
	switch {
	case errors.As(err, &ie) && ie.Status == http.StatusBadRequest:
		return nil, failStep(StepChange, sentenceClaimRefused, err)
	case err != nil:
		return nil, written(err)
	}
	return map[string]any{"outcome": outcomeChanged, "claims": len(values)}, nil
}
