package busauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Every join token names the role of the node it was minted for, in
// bus_tokens.role (auth consolidation 1A.8).
//
// Where the role comes from:
//
//   - MintBound takes it from its caller: POST /api/bus/tokens resolves it from
//     the request (ResolveRole), and the controlplane's own agent token is
//     minted as proto.RoleControlPlane (EnsureAgentToken).
//   - A preseed entry carries it (PreseedToken.Role), or, in a manifest written
//     before that field existed, as its label — rasputin-provision has always
//     written the node's role there.
//   - A row written before the column existed is backfilled by OpenStore: the
//     row carrying the self_agent marker is the controlplane's own agent, so it
//     becomes proto.RoleControlPlane; any other row whose label is exactly a
//     role (the Add-node wizard and rasputin-provision both label a token with
//     its role) takes that role.
//
// A row still naming no role after that is a legacy token nothing can place,
// and Validate refuses it, the same way it refuses a legacy unbound token
// (geekdojo-brain#423). The refusal is logged with the token's id, and the
// api logs how many live ones exist at every start (CountActiveRoleless).

// ErrNoRole is returned (wrapped) wherever a token's role is missing or is not
// one of proto.AllRoles.
var ErrNoRole = errors.New("join token has no valid node role")

// noRoleRemedy is the operator-facing half of every refusal of a role-less
// token: what happened and what to do.
const noRoleRemedy = "the token names no node role (it predates role binding and its label is not a role), so the bus refuses it; revoke it (DELETE /api/bus/tokens/{id}) and mint a replacement for the node with its role"

// roleList is proto.AllRoles, joined for error messages.
func roleList() string {
	parts := make([]string, len(proto.AllRoles))
	for i, r := range proto.AllRoles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}

// checkRole returns a wrapped ErrNoRole when role is not one of proto.AllRoles.
func checkRole(role proto.NodeRole) error {
	if !proto.ValidRole(role) {
		return fmt.Errorf("%w: %q is not one of %s", ErrNoRole, role, roleList())
	}
	return nil
}

// ResolveRole returns the role a token is for: role when it is set, else the
// label when the label is exactly a role. role, when set, must be valid — it is
// never silently replaced by the label. Shared by preload and the api's mint
// handler, so both read a request the same way.
func ResolveRole(role proto.NodeRole, label string) (proto.NodeRole, error) {
	if role != "" {
		if err := checkRole(role); err != nil {
			return "", err
		}
		return role, nil
	}
	if r := proto.NodeRole(label); proto.ValidRole(r) {
		return r, nil
	}
	return "", fmt.Errorf("%w: no role given and the label %q is not one of %s", ErrNoRole, label, roleList())
}

// backfillRoles fills bus_tokens.role on every row that has none but says what
// it is: the self_agent row first (it is the controlplane's own agent whatever
// its label reads), then every row whose label is exactly a role. Idempotent,
// and run on every OpenStore.
func backfillRoles(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
        UPDATE bus_tokens SET role = ?
        WHERE (role IS NULL OR role = '') AND self_agent = 1`, string(proto.RoleControlPlane)); err != nil {
		return fmt.Errorf("busauth: backfill the controlplane agent token's role: %w", err)
	}
	for _, r := range proto.AllRoles {
		if _, err := db.ExecContext(ctx, `
            UPDATE bus_tokens SET role = ?
            WHERE (role IS NULL OR role = '') AND label = ?`, string(r), string(r)); err != nil {
			return fmt.Errorf("busauth: backfill role %q from labels: %w", r, err)
		}
	}
	return nil
}

// CountActiveRoleless returns how many live (unrevoked), bound tokens name no
// valid role. Validate refuses every one of them, so a nonzero count means a
// node seeded with one cannot join; the api logs it at startup, and the tokens
// are listed by GET /api/bus/tokens with no role. Unbound tokens are counted by
// CountActiveUnbound instead, so a token is reported once.
func (s *Store) CountActiveRoleless(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT role FROM bus_tokens
        WHERE revoked_at IS NULL AND node_id IS NOT NULL AND node_id != ''`)
	if err != nil {
		return 0, fmt.Errorf("busauth: count role-less tokens: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var role sql.NullString
		if err := rows.Scan(&role); err != nil {
			return 0, fmt.Errorf("busauth: count role-less tokens: %w", err)
		}
		if !role.Valid || !proto.ValidRole(proto.NodeRole(role.String)) {
			n++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("busauth: count role-less tokens: %w", err)
	}
	return n, nil
}
