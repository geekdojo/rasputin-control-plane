package move

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// OldUsers is the pre-update operators (*auth.Store).
type OldUsers interface {
	CountUsers(ctx context.Context) (int, error)
	ListUsers(ctx context.Context) ([]*auth.User, error)
}

// Persons is the realm's persons (*accounts.Users).
type Persons interface {
	People(ctx context.Context) ([]accounts.Account, error)
	Read(ctx context.Context, sub string) (accounts.Person, error)
}

// Removed is the removed-name list (*removednames.Store).
type Removed interface {
	Removed(ctx context.Context, name, email string) (bool, error)
}

// State is the move's facts: whether a move is pending (Identity 5.5's
// commit gate reads it, geekdojo/geekdojo-brain#1008), and C9's state,
// which a repair session's re-run needs.
type State struct {
	old     OldUsers
	records Records
	persons Persons
	removed Removed
}

// NewState returns the State over its collaborators. It refuses a nil one
// and does no I/O.
func NewState(old OldUsers, records Records, persons Persons, removed Removed) (*State, error) {
	if old == nil || records == nil || persons == nil || removed == nil {
		return nil, errors.New("move: NewState: a collaborator is nil")
	}
	return &State{old: old, records: records, persons: persons, removed: removed}, nil
}

// Pending reports whether old operators exist and no move is recorded.
// Every read error is returned, never read as false (ERR-CLOSED).
func (s *State) Pending(ctx context.Context) (bool, error) {
	n, err := s.old.CountUsers(ctx)
	if err != nil {
		return false, fmt.Errorf("move: count the old users: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	rec, err := s.records.Recorded(ctx)
	if err != nil {
		return false, err
	}
	return !rec, nil
}

// Repair is C9's state: Holds when the realm has no person, old operators
// exist, a move is recorded, and at least one old operator is not on the
// removed-name list. Accounts is how many would come back; Token is the
// state the person confirms, which changes when the set does.
type Repair struct {
	Holds    bool
	Accounts int
	Token    string
}

// tokenPrefix is folded into the state token, so it is never a hash of
// ids alone.
const tokenPrefix = "identity.move/c9\n"

// oldUsers reads the old operators as the move maps them.
func oldUsers(ctx context.Context, src OldUsers) ([]OldUser, error) {
	us, err := src.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("move: list the old users: %w", err)
	}
	out := make([]OldUser, 0, len(us))
	for _, u := range us {
		if u == nil {
			return nil, errors.New("move: the old users hold a nil user")
		}
		out = append(out, OldUser{Handle: u.ID, Name: u.Name, DisplayName: u.DisplayName, CreatedAt: u.CreatedAt})
	}
	return out, nil
}

// kept is ms without those the removed-name list reports, and how many
// were left out. An unreadable list is an error.
func kept(ctx context.Context, removed Removed, ms []Mapping) ([]Mapping, int, error) {
	out := make([]Mapping, 0, len(ms))
	for _, m := range ms {
		gone, err := removed.Removed(ctx, m.To, "")
		if err != nil {
			return nil, 0, fmt.Errorf("move: read the removed-name list: %w", err)
		}
		if !gone {
			out = append(out, m)
		}
	}
	return out, len(ms) - len(out), nil
}

// Repair reads C9's state. Each read error is returned.
func (s *State) Repair(ctx context.Context) (Repair, error) {
	people, err := s.persons.People(ctx)
	if err != nil {
		return Repair{}, fmt.Errorf("move: list the realm's persons: %w", err)
	}
	n, err := s.old.CountUsers(ctx)
	if err != nil {
		return Repair{}, fmt.Errorf("move: count the old users: %w", err)
	}
	rec, err := s.records.Recorded(ctx)
	if err != nil {
		return Repair{}, err
	}
	old, err := oldUsers(ctx, s.old)
	if err != nil {
		return Repair{}, err
	}
	ms, err := Map(old, nil)
	if err != nil {
		return Repair{}, err
	}
	back, _, err := kept(ctx, s.removed, ms)
	if err != nil {
		return Repair{}, err
	}
	ids := make([]string, 0, len(back))
	for _, m := range back {
		ids = append(ids, m.AccountID)
	}
	slices.Sort(ids)
	sum := sha256.Sum256([]byte(tokenPrefix + strings.Join(ids, "\n")))
	return Repair{
		Holds:    len(people) == 0 && n > 0 && rec && len(back) > 0,
		Accounts: len(back),
		Token:    hex.EncodeToString(sum[:]),
	}, nil
}

// RepairToken is C9's state as the kind table reads it
// (authz.MoveState).
func (s *State) RepairToken(ctx context.Context) (string, bool, error) {
	r, err := s.Repair(ctx)
	if err != nil {
		return "", false, err
	}
	return r.Token, r.Holds, nil
}
