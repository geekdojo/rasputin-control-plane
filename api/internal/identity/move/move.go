package move

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Kind is the move's job kind: a System job, so POST /api/jobs refuses it.
// The kind table lets a repair session submit it in C9's state.
const Kind = "identity.move"

// The steps, in order.
const (
	StepCheck  = "check"
	StepImport = "import"
	StepRecord = "record"
)

// The outcomes.
const (
	outcomeNotNeeded = "not_needed"
	outcomeDue       = "due"
	outcomeImported  = "imported"
	outcomeRecorded  = "recorded"
)

// The modes a step logs.
const (
	modeSystem = "system"
	modeRepair = "repair"
)

// The failure sentences a person reads on the job (ERR-MESSAGE).
const (
	sentenceMove     = "Rasputin couldn't move the accounts from before the update. It tries again the next time sign-in becomes ready."
	sentenceNotReady = "Sign-in isn't ready, so the accounts weren't moved. It tries again the next time sign-in becomes ready."
	sentenceSpec     = "Rasputin couldn't read this request, so no account was moved."
)

// The causes an identity.move.failed record carries: a fixed code for what
// failed, which names no account (LOG-STRUCT).
const (
	causeSpec           = "spec"
	causeNotReady       = "not_ready"
	causeStateRead      = "state_read"
	causeMoveState      = "move_state"
	causeStateChanged   = "state_changed"
	causeOldUsers       = "old_users"
	causeRealmRead      = "realm_read"
	causeRecordsRead    = "records_read"
	causeMapping        = "mapping"
	causeRemovedList    = "removed_list"
	causeAccessFact     = "access_fact"
	causeDesignation    = "designation"
	causePartialImport  = "partial_import"
	causeReadBack       = "read_back"
	causeReadBackName   = "read_back_name"
	causeReadBackAccess = "read_back_access"
	causeResult         = "result"
	causeRecord         = "record"
)

// Spec is the move's spec: system mode, or a repair session's re-run with
// the state token it confirmed. It carries no name.
type Spec struct {
	Repair     bool   `json:"repair"`
	StateToken string `json:"stateToken,omitempty"`
}

// Admin is the Admin API session (*idclient.Session).
type Admin interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// Designations writes the moved designation (*accounts.Designations).
type Designations interface {
	DesignateMoved(ctx context.Context, sub string) error
}

// Facts records the app-access fact (removednames.AccessFacts).
type Facts interface {
	Record(ctx context.Context, sub string) error
}

// Ready is the identity service's readiness (*identitystate.Monitor).
type Ready interface {
	Ready(ctx context.Context) error
}

// Deps are a Mover's collaborators. New refuses a missing one.
type Deps struct {
	Admin        Admin
	OldUsers     OldUsers
	Persons      Persons
	Designations Designations
	Facts        Facts
	Removed      Removed
	Ready        Ready
	Records      Records
	// Lock is the one accounts lock, held around the import.
	Lock sync.Locker
	// Realm is the realm the accounts go to: rasputin.
	Realm string
	Now   func() time.Time
	Log   *slog.Logger
	// StepTimeout bounds each step; it marks work gone far outside normal
	// and decides nothing else.
	StepTimeout time.Duration
}

// Mover runs identity.move.
type Mover struct {
	d     Deps
	state *State
	log   *slog.Logger
}

// New checks d and returns a Mover. It does no I/O.
func New(d Deps) (*Mover, error) {
	if d.Admin == nil || d.OldUsers == nil || d.Persons == nil || d.Designations == nil || d.Facts == nil ||
		d.Removed == nil || d.Ready == nil || d.Records == nil || d.Lock == nil || d.Now == nil || d.Log == nil {
		return nil, errors.New("move: New: a collaborator is nil")
	}
	if d.Realm == "" {
		return nil, errors.New("move: New: Realm is empty")
	}
	if d.StepTimeout <= 0 {
		return nil, fmt.Errorf("move: New: StepTimeout %v is not positive", d.StepTimeout)
	}
	st, err := NewState(d.OldUsers, d.Records, d.Persons, d.Removed)
	if err != nil {
		return nil, err
	}
	return &Mover{d: d, state: st, log: d.Log.With("component", "identity")}, nil
}

// stepError is a step's failure: the sentence the runner records as the
// job's error, the fixed cause code the log carries, and the error, which
// names the step.
type stepError struct {
	sentence string
	cause    string
	err      error
}

func (e *stepError) Error() string { return e.sentence }
func (e *stepError) Unwrap() error { return e.err }

func fail(step, sentence, cause string, err error) error {
	return &stepError{sentence: sentence, cause: cause, err: fmt.Errorf("%s: %w", step, err)}
}

// Workflow is the move: check, import, record. A failure stops the job and
// writes no move row, so the move stays pending.
func (m *Mover) Workflow() jobs.Workflow {
	mk := func(name string, do func(sc *jobs.StepCtx, spec Spec) (map[string]any, error)) jobs.WorkflowStep {
		return jobs.WorkflowStep{Name: name, Timeout: m.d.StepTimeout, Do: m.wrap(name, do)}
	}
	return jobs.Workflow{Kind: Kind, System: true, Steps: []jobs.WorkflowStep{
		mk(StepCheck, m.check),
		mk(StepImport, m.importAccounts),
		mk(StepRecord, m.record),
	}}
}

// wrap decodes the spec, runs do unless the check found nothing to do,
// and writes the step's one INFO line, or one ERROR line on a failure.
func (m *Mover) wrap(name string, do func(sc *jobs.StepCtx, spec Spec) (map[string]any, error)) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		var spec Spec
		if err := json.Unmarshal(sc.Spec, &spec); err != nil {
			return nil, m.failed(sc, name, modeSystem, fail(name, sentenceSpec, causeSpec, err))
		}
		mode := modeSystem
		if spec.Repair {
			mode = modeRepair
		}
		out := map[string]any{"outcome": outcomeNotNeeded}
		if name == StepCheck || outcomeOf(sc.PriorResults[StepCheck]) == outcomeDue {
			var err error
			if out, err = do(sc, spec); err != nil {
				return nil, m.failed(sc, name, mode, err)
			}
		}
		attrs := []any{"event", "identity.move.step", "step", name, "outcome", out["outcome"], "mode", mode}
		if c, ok := out["counts"].(counts); ok {
			attrs = append(attrs, "accounts", c.Accounts, "renamed", c.Renamed, "left_out", c.LeftOut)
			delete(out, "counts")
		}
		b, err := json.Marshal(out)
		if err != nil {
			return nil, m.failed(sc, name, mode, fail(name, sentenceMove, causeResult, err))
		}
		jobs.LogStep(m.log, sc, slog.LevelInfo, name+": "+fmt.Sprint(out["outcome"]), attrs...)
		return b, nil
	}
}

func outcomeOf(raw json.RawMessage) string {
	var o struct {
		Outcome string `json:"outcome"`
	}
	if raw == nil || json.Unmarshal(raw, &o) != nil {
		return ""
	}
	return o.Outcome
}

// failed writes the failure's one ERROR record: the step, the mode, the
// cause code, and an Admin API error's status and kind, never a name, an
// email or an id.
func (m *Mover) failed(sc *jobs.StepCtx, name, mode string, err error) error {
	attrs := []any{"event", "identity.move.failed", "step", name, "mode", mode}
	var se *stepError
	if errors.As(err, &se) {
		attrs = append(attrs, "cause", se.cause)
	}
	var ie *idclient.Error
	if errors.As(err, &ie) {
		attrs = append(attrs, "status", ie.Status, "kind", fmt.Sprint(ie.Kind))
	}
	jobs.LogStep(m.log, sc, slog.LevelError, name+": failed", attrs...)
	return err
}

// check is step 1, which holds every refusal: the service must be ready;
// in system mode nothing pending is not_needed; in repair mode C9's state
// must still hold with the confirmed token.
func (m *Mover) check(sc *jobs.StepCtx, spec Spec) (map[string]any, error) {
	ctx := sc.Ctx
	if err := m.d.Ready.Ready(ctx); err != nil {
		return nil, fail(StepCheck, sentenceNotReady, causeNotReady, err)
	}
	if !spec.Repair {
		pending, err := m.state.Pending(ctx)
		switch {
		case err != nil:
			return nil, fail(StepCheck, sentenceMove, causeStateRead, err)
		case !pending:
			return map[string]any{"outcome": outcomeNotNeeded}, nil
		}
		return map[string]any{"outcome": outcomeDue}, nil
	}
	r, err := m.state.Repair(ctx)
	switch {
	case err != nil:
		return nil, fail(StepCheck, sentenceMove, causeStateRead, err)
	case !r.Holds:
		return nil, fail(StepCheck, authz.KindSentence(authz.CodeMoveState), causeMoveState, errors.New("C9's state does not hold"))
	case spec.StateToken == "" || r.Token != spec.StateToken:
		return nil, fail(StepCheck, authz.KindSentence(authz.CodeStateChanged), causeStateChanged, errors.New("the state token changed"))
	}
	return map[string]any{"outcome": outcomeDue}, nil
}

// Moved is one account in the import's result: the mapping shown in the
// Job.
type Moved struct {
	AccountID string `json:"accountId"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// importResult is the import step's result.
type importResult struct {
	Outcome  string  `json:"outcome"`
	Accounts []Moved `json:"accounts"`
	LeftOut  int     `json:"leftOut"`
}

// counts are a step's logged counts.
type counts struct{ Accounts, Renamed, LeftOut int }

// importUser is one user of the partialImport body.
type importUser struct {
	ID              string              `json:"id"`
	Username        string              `json:"username"`
	Enabled         bool                `json:"enabled"`
	FirstName       string              `json:"firstName,omitempty"`
	Attributes      map[string][]string `json:"attributes"`
	RequiredActions []string            `json:"requiredActions"`
	RealmRoles      []string            `json:"realmRoles"`
}

// importBody is the partialImport body: users only, SKIP for an id that
// exists under the same name, so a re-run changes nothing already
// imported. An existing id under another name is a 409 at Keycloak 26.8.2
// (K-PARTIALIMPORT), so mappings keeps each held name.
type importBody struct {
	IfResourceExists string       `json:"ifResourceExists"`
	Users            []importUser `json:"users"`
}

// mappings maps the old operators. A moved account the realm already
// holds keeps the sign-in name it holds there, so a re-run never sends an
// existing id under another name (which partialImport answers 409); other
// operators are mapped around those names and around the names accounts
// that are not moved ones hold, such as a door sign-up. In repair mode
// each recorded account is mapped to its recorded new name, and each the
// removed-name list reports under that name is left out. A failure is a
// stepError with its cause.
func (m *Mover) mappings(ctx context.Context, repair bool) ([]Mapping, int, error) {
	old, err := oldUsers(ctx, m.d.OldUsers)
	if err != nil {
		return nil, 0, fail(StepImport, sentenceMove, causeOldUsers, err)
	}
	people, err := m.d.Persons.People(ctx)
	if err != nil {
		return nil, 0, fail(StepImport, sentenceMove, causeRealmRead, fmt.Errorf("list the realm's persons: %w", err))
	}
	ids := make(map[string]bool, len(old))
	for _, u := range old {
		ids[auth.MovedAccountID(u.Handle)] = true
	}
	taken, keep := map[string]bool{}, map[string]string{}
	for _, p := range people {
		switch {
		case p.Username == "":
		case ids[p.ID]:
			keep[p.ID] = p.Username
		default:
			taken[p.Username] = true
		}
	}
	if repair {
		rows, err := m.d.Records.Rows(ctx)
		if err != nil {
			return nil, 0, fail(StepImport, sentenceMove, causeRecordsRead, err)
		}
		recordedNames(rows, keep)
	}
	ms, err := mapKeeping(old, taken, keep)
	if err != nil {
		return nil, 0, fail(StepImport, sentenceMove, causeMapping, err)
	}
	if !repair {
		return ms, 0, nil
	}
	back, leftOut, err := kept(ctx, m.d.Removed, ms)
	if err != nil {
		return nil, 0, fail(StepImport, sentenceMove, causeRemovedList, err)
	}
	return back, leftOut, nil
}

// importAccounts is step 2, under the accounts lock: the names mapped, the
// app-access fact and the designation written for each account, one
// partialImport, then each account read back by id.
func (m *Mover) importAccounts(sc *jobs.StepCtx, spec Spec) (map[string]any, error) {
	ctx := sc.Ctx
	m.d.Lock.Lock()
	defer m.d.Lock.Unlock()
	ms, leftOut, err := m.mappings(ctx, spec.Repair)
	if err != nil {
		return nil, err
	}
	for _, x := range ms {
		if err := m.d.Facts.Record(ctx, x.AccountID); err != nil {
			return nil, fail(StepImport, sentenceMove, causeAccessFact, fmt.Errorf("record the app-access fact: %w", err))
		}
	}
	for _, x := range ms {
		if err := m.d.Designations.DesignateMoved(ctx, x.AccountID); err != nil {
			return nil, fail(StepImport, sentenceMove, causeDesignation, fmt.Errorf("designate: %w", err))
		}
	}
	body := importBody{IfResourceExists: "SKIP", Users: make([]importUser, 0, len(ms))}
	for _, x := range ms {
		body.Users = append(body.Users, importUser{
			ID: x.AccountID, Username: x.To, Enabled: true, FirstName: x.User.DisplayName,
			Attributes:      map[string][]string{accounts.AttrAppRole: {string(accounts.AppUser)}},
			RequiredActions: []string{flows.ActionRecoveryCodes},
			RealmRoles:      []string{"offline_access"},
		})
	}
	if len(body.Users) > 0 {
		path := "/admin/realms/" + url.PathEscape(m.d.Realm) + "/partialImport"
		if _, err := m.d.Admin.Admin(ctx, http.MethodPost, path, body, nil); err != nil {
			return nil, fail(StepImport, sentenceMove, causePartialImport, fmt.Errorf("partial import: %w", err))
		}
	}
	res := importResult{Outcome: outcomeImported, Accounts: make([]Moved, 0, len(ms)), LeftOut: leftOut}
	renamed := 0
	for _, x := range ms {
		p, err := m.d.Persons.Read(ctx, x.AccountID)
		switch {
		case err != nil:
			return nil, fail(StepImport, sentenceMove, causeReadBack, fmt.Errorf("read back: %w", err))
		case p.Username != x.To:
			return nil, fail(StepImport, sentenceMove, causeReadBackName, errors.New("read back: the account holds another sign-in name"))
		case p.AppRole == "":
			return nil, fail(StepImport, sentenceMove, causeReadBackAccess, errors.New("read back: the account holds no app access"))
		}
		if x.From != x.To {
			renamed++
		}
		res.Accounts = append(res.Accounts, Moved{AccountID: x.AccountID, From: x.From, To: x.To})
	}
	return map[string]any{"outcome": res.Outcome, "accounts": res.Accounts, "leftOut": res.LeftOut,
		"counts": counts{Accounts: len(ms), Renamed: renamed, LeftOut: leftOut}}, nil
}

// record is step 3: the move rows from the import's result, written last.
func (m *Mover) record(sc *jobs.StepCtx, _ Spec) (map[string]any, error) {
	ctx := sc.Ctx
	var res importResult
	if err := json.Unmarshal(sc.PriorResults[StepImport], &res); err != nil {
		return nil, fail(StepRecord, sentenceMove, causeResult, fmt.Errorf("read the import's result: %w", err))
	}
	us, err := m.d.OldUsers.ListUsers(ctx)
	if err != nil {
		return nil, fail(StepRecord, sentenceMove, causeOldUsers, fmt.Errorf("list the old users: %w", err))
	}
	handles := make(map[string][]byte, len(us))
	for _, u := range us {
		if u != nil {
			handles[auth.MovedAccountID(u.ID)] = u.ID
		}
	}
	now := m.d.Now().UTC()
	rows := make([]Row, 0, len(res.Accounts))
	for _, a := range res.Accounts {
		h, ok := handles[a.AccountID]
		if !ok {
			return nil, fail(StepRecord, sentenceMove, causeOldUsers, errors.New("a moved account's old user is gone"))
		}
		rows = append(rows, Row{Handle: h, AccountID: a.AccountID, OldName: a.From, NewName: a.To, MovedAt: now})
	}
	if err := m.d.Records.Record(ctx, rows); err != nil {
		return nil, fail(StepRecord, sentenceMove, causeRecord, err)
	}
	return map[string]any{"outcome": outcomeRecorded, "counts": counts{Accounts: len(rows)}}, nil
}
