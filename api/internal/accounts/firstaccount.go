package accounts

import (
	"context"
	"errors"
	"slices"
)

// People lists the realm's persons (*Users).
type People interface {
	People(ctx context.Context) ([]Account, error)
}

// FirstAccount names the realm's earliest-created person: the account the
// first-run claim designates (D13: the first account created, not the first
// to finish; geekdojo/geekdojo-brain#990). It is auth.Claimer.
type FirstAccount struct{ people People }

// NewFirstAccount returns FirstAccount over people.
func NewFirstAccount(people People) (*FirstAccount, error) {
	if people == nil {
		return nil, errors.New("accounts: NewFirstAccount: people is nil")
	}
	return &FirstAccount{people: people}, nil
}

// errNoPerson is Earliest's answer for a realm with no person.
var errNoPerson = errors.New("accounts: the realm holds no person")

// Earliest is the id of the person with the lowest createdTimestamp, ties
// going to the lower id. A realm with no person is an error, and so is any
// error listing them.
func (f *FirstAccount) Earliest(ctx context.Context) (string, error) {
	all, err := f.people.People(ctx)
	if err != nil {
		return "", err
	}
	if len(all) == 0 {
		return "", errNoPerson
	}
	first := slices.MinFunc(all, func(a, b Account) int {
		switch {
		case a.Created != b.Created:
			if a.Created < b.Created {
				return -1
			}
			return 1
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	return first.ID, nil
}
