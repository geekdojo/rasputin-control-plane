// Package sessions ends a person's sessions at the identity service
// (geekdojo/geekdojo-brain#991, Identity 4.9): the one session-ending
// primitive. identity.revoke's online and offline steps and the accounts
// Access grant call it, Identity 4.10's password resets
// (geekdojo/geekdojo-brain#992) call EndAll, and Identity 4.12's sign-out
// everywhere else (geekdojo/geekdojo-brain#994) calls EndAllExcept.
//
// Nothing here logs. An error carries the Admin API's path, which names the
// account, so a caller logs only its status and kind.
package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// Realm is the realm every account is in.
const Realm = "rasputin"

// clientPage is how many clients one read of the realm's clients asks for.
const clientPage = 100

// AdminCaller is the Admin API session (*idclient.Session).
type AdminCaller interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Ender ends one person's identity sessions.
type Ender struct {
	Admin AdminCaller
}

func realmPath() string { return "/admin/realms/" + url.PathEscape(Realm) }

func userPath(sub string) string { return realmPath() + "/users/" + url.PathEscape(sub) }

// EndAll ends every online session of sub and sets the account's
// not-before, so no token issued before now refreshes: POST
// /users/{id}/logout. The identity service sends each relying party with a
// back-channel URL its logout token.
func (e Ender) EndAll(ctx context.Context, sub string) error {
	if sub == "" {
		return errors.New("sessions: end online sessions: no account id")
	}
	if _, err := e.Admin.Admin(ctx, http.MethodPost, userPath(sub)+"/logout", nil, nil); err != nil {
		return fmt.Errorf("sessions: end online sessions: %w", err)
	}
	return nil
}

// EndAllExcept ends every online session of sub but keep, the session the
// request came from (geekdojo/geekdojo-brain#994, "sign out everywhere
// else"): it lists the account's sessions (GET /users/{id}/sessions) and
// deletes each other one (DELETE /sessions/{sid}). It sets no not-before,
// since that would end keep too. A session gone by the time it is deleted
// counts as ended. It returns how many it ended.
func (e Ender) EndAllExcept(ctx context.Context, sub, keep string) (int, error) {
	if sub == "" || keep == "" {
		return 0, errors.New("sessions: end other sessions: no account id or no session to keep")
	}
	var found []struct {
		ID string `json:"id"`
	}
	if _, err := e.Admin.Admin(ctx, http.MethodGet, userPath(sub)+"/sessions", nil, &found); err != nil {
		return 0, fmt.Errorf("sessions: end other sessions: read: %w", err)
	}
	n := 0
	for _, s := range found {
		if s.ID == "" || s.ID == keep {
			continue
		}
		_, err := e.Admin.Admin(ctx, http.MethodDelete, realmPath()+"/sessions/"+url.PathEscape(s.ID), nil, nil)
		if err != nil && !errors.Is(err, idclient.ErrNotFound) {
			return n, fmt.Errorf("sessions: end other sessions: delete: %w", err)
		}
		n++
	}
	return n, nil
}

// EndOffline deletes every offline session of sub: for each client of the
// realm it reads the account's offline sessions there and deletes each one
// it has not deleted yet. It returns how many it deleted. A session another
// client's read already named, or one gone by the time it is deleted, is
// not counted twice.
func (e Ender) EndOffline(ctx context.Context, sub string) (int, error) {
	if sub == "" {
		return 0, errors.New("sessions: end offline sessions: no account id")
	}
	clients, err := e.clients(ctx)
	if err != nil {
		return 0, fmt.Errorf("sessions: end offline sessions: %w", err)
	}
	ended := map[string]bool{}
	for _, c := range clients {
		var found []struct {
			ID string `json:"id"`
		}
		if _, err := e.Admin.Admin(ctx, http.MethodGet, userPath(sub)+"/offline-sessions/"+url.PathEscape(c), nil, &found); err != nil {
			return len(ended), fmt.Errorf("sessions: end offline sessions: read: %w", err)
		}
		for _, s := range found {
			if s.ID == "" || ended[s.ID] {
				continue
			}
			_, err := e.Admin.Admin(ctx, http.MethodDelete, realmPath()+"/sessions/"+url.PathEscape(s.ID)+"?isOffline=true", nil, nil)
			if err != nil && !errors.Is(err, idclient.ErrNotFound) {
				return len(ended), fmt.Errorf("sessions: end offline sessions: delete: %w", err)
			}
			ended[s.ID] = true
		}
	}
	return len(ended), nil
}

// clients is the internal id of every client in the realm, read a page at a
// time until a page comes back short.
func (e Ender) clients(ctx context.Context) ([]string, error) {
	var ids []string
	for first := 0; ; first += clientPage {
		var page []struct {
			ID string `json:"id"`
		}
		path := realmPath() + "/clients?first=" + strconv.Itoa(first) + "&max=" + strconv.Itoa(clientPage)
		if _, err := e.Admin.Admin(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, fmt.Errorf("read the clients: %w", err)
		}
		for _, c := range page {
			if c.ID != "" {
				ids = append(ids, c.ID)
			}
		}
		if len(page) < clientPage {
			return ids, nil
		}
	}
}
