package events

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// detailCredentialType is the event detail naming a credential's type
// (Keycloak's Details.CREDENTIAL_TYPE).
const detailCredentialType = "credential_type"

// pageSize is how many events one Admin API call asks for.
const pageSize = 100

// Deps are the drain's collaborators. New refuses a missing one; the sink
// lists may be empty.
type Deps struct {
	Admin  Admin
	Marks  Marks
	Signal *Signal
	// Realm is the realm whose events are drained: rasputin.
	Realm      string
	UserSinks  []UserSink
	AdminSinks []AdminSink
	PassSinks  []PassSink
	Log        *slog.Logger
}

// Drainer is the drain. Run is its one goroutine.
type Drainer struct {
	d      Deps
	log    *slog.Logger
	passes atomic.Uint64

	mu     sync.Mutex
	behind bool
	// warned are the once-per-outage WARN flags, by operation.
	warned map[string]bool
}

// New checks d and returns a Drainer. It does no I/O.
func New(d Deps) (*Drainer, error) {
	switch {
	case d.Admin == nil:
		return nil, errors.New("events: Deps.Admin is nil")
	case d.Marks == nil:
		return nil, errors.New("events: Deps.Marks is nil")
	case d.Signal == nil:
		return nil, errors.New("events: Deps.Signal is nil")
	case d.Realm == "":
		return nil, errors.New("events: Deps.Realm is empty")
	case d.Log == nil:
		return nil, errors.New("events: Deps.Log is nil")
	}
	return &Drainer{d: d, log: d.Log.With("component", "identity"), warned: map[string]bool{}}, nil
}

// MarkDirty marks the drain's signal.
func (dr *Drainer) MarkDirty() { dr.d.Signal.MarkDirty() }

// Begin records a request that can store an event on the drain's signal
// (Signal.Begin).
func (dr *Drainer) Begin() (end func()) { return dr.d.Signal.Begin() }

// Pass is the number of passes started so far.
func (dr *Drainer) Pass() uint64 { return dr.passes.Load() }

// Behind is the history-behind fact: the last pass could not read or store
// the events or a mark. It is false before the first pass.
func (dr *Drainer) Behind(context.Context) (bool, error) {
	dr.mu.Lock()
	defer dr.mu.Unlock()
	return dr.behind, nil
}

// Run runs one pass each time the signal is marked, until ctx ends.
func (dr *Drainer) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-dr.d.Signal.ch:
			dr.pass(ctx)
		}
	}
}

// pass drains both streams once and reports its start and end.
func (dr *Drainer) pass(ctx context.Context) {
	n := dr.passes.Add(1)
	for _, s := range dr.d.PassSinks {
		s.PassStarted(ctx, n)
	}
	userErr := drain(ctx, dr, "events.user", "/admin/realms/"+url.PathEscape(dr.d.Realm)+"/events", UserMarkKey,
		func(e userRep) {
			ev := e.event()
			for _, s := range dr.d.UserSinks {
				s.UserEvent(ctx, ev)
			}
		})
	adminErr := drain(ctx, dr, "events.admin", "/admin/realms/"+url.PathEscape(dr.d.Realm)+"/admin-events", AdminMarkKey,
		func(e adminRep) {
			ev := e.event()
			for _, s := range dr.d.AdminSinks {
				s.AdminEvent(ctx, ev)
			}
		})
	dr.mu.Lock()
	dr.behind = userErr != nil || adminErr != nil
	dr.mu.Unlock()
	for _, s := range dr.d.PassSinks {
		s.PassEnded(ctx, n)
	}
}

// outage logs err at WARN once per run of failures of op, and clears the flag
// on a nil err.
func (dr *Drainer) outage(ctx context.Context, op, msg string, err error) {
	dr.mu.Lock()
	warn := err != nil && !dr.warned[op]
	dr.warned[op] = err != nil
	dr.mu.Unlock()
	if warn {
		dr.log.LogAttrs(ctx, slog.LevelWarn, msg, slog.String("op", op), slog.String("err", err.Error()))
	}
}

// ---- the stored forms ------------------------------------------------------

// stored is what the drain needs of an event to page and mark it.
type stored interface {
	key() string
	ms() int64
}

// userRep is Keycloak's EventRepresentation, the fields the drain reads.
type userRep struct {
	ID        string            `json:"id"`
	Time      int64             `json:"time"`
	Type      string            `json:"type"`
	ClientID  string            `json:"clientId"`
	UserID    string            `json:"userId"`
	IPAddress string            `json:"ipAddress"`
	Error     string            `json:"error"`
	Details   map[string]string `json:"details"`
}

func (e userRep) ms() int64 { return e.Time }

func (e userRep) key() string {
	if e.ID != "" {
		return e.ID
	}
	return synthetic(strconv.FormatInt(e.Time, 10), e.Type, e.ClientID, e.UserID, e.IPAddress, e.Error)
}

func (e userRep) event() UserEvent {
	ip, err := netip.ParseAddr(e.IPAddress)
	if err != nil {
		ip = netip.Addr{}
	}
	return UserEvent{ID: e.key(), Time: time.UnixMilli(e.Time), Type: e.Type, ClientID: e.ClientID,
		UserID: e.UserID, Error: e.Error, IP: ip, CredentialType: e.Details[detailCredentialType]}
}

// adminRep is Keycloak's AdminEventRepresentation, the fields the drain
// reads.
type adminRep struct {
	ID            string `json:"id"`
	Time          int64  `json:"time"`
	OperationType string `json:"operationType"`
	ResourceType  string `json:"resourceType"`
	ResourcePath  string `json:"resourcePath"`
}

func (e adminRep) ms() int64 { return e.Time }

func (e adminRep) key() string {
	if e.ID != "" {
		return e.ID
	}
	return synthetic(strconv.FormatInt(e.Time, 10), e.OperationType, e.ResourceType, e.ResourcePath)
}

func (e adminRep) event() AdminEvent {
	return AdminEvent{ID: e.key(), Time: time.UnixMilli(e.Time), OperationType: e.OperationType, ResourceType: e.ResourceType,
		ResourcePath: e.ResourcePath}
}

// synthetic is the key of an event stored with no id: a hash of its fields,
// so the mark holds no user id or address in the clear.
func synthetic(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return "h:" + hex.EncodeToString(h.Sum(nil)[:16])
}

// ---- the mark --------------------------------------------------------------

// mark is a stream's mark: a floor time in milliseconds, before which every
// stored event has been delivered, and the keys of every delivered event at
// or after it. The floor is the newest event time delivered, held back to the
// start of the oldest request still open when the pass began (the signal's
// horizon), so an event committed after a later-stamped one was read is still
// at or after the floor on the next pass.
type mark struct {
	Time int64    `json:"time"`
	IDs  []string `json:"ids"`
}

// readMark reads the stored mark. Absent, or malformed (one WARN), is no
// mark: everything stored is new. A read that fails is an error.
func (dr *Drainer) readMark(ctx context.Context, op, key string) (mark, bool, error) {
	raw, err := dr.d.Marks.Get(ctx, key)
	if err != nil {
		return mark{}, false, fmt.Errorf("events: read the mark %s: %w", key, err)
	}
	if raw == "" {
		return mark{}, false, nil
	}
	var m mark
	err = json.Unmarshal([]byte(raw), &m)
	if err == nil && m.Time <= 0 {
		err = errors.New("the mark holds no time")
	}
	dr.outage(ctx, op+".mark", "sign-in history mark unreadable; reading every stored event as new", err)
	if err != nil {
		return mark{}, false, nil
	}
	return m, true, nil
}

// ---- one stream ------------------------------------------------------------

// drain reads one stream from its mark's floor, oldest first, then delivers
// the events it has not delivered before, then stores the new mark. It
// delivers nothing when a read fails.
//
// The service orders events by time alone, with no tie-breaker
// (JpaEventQuery and JpaAdminEventQuery at 26.8.2), so two offset pages can
// order the events of one millisecond differently and drop one between them.
// So every read starts at a time (dateFrom, inclusive) with first unset:
// from one query sorted by time, every event stamped before that page's last
// time is in the page, and the next read starts at that last time. A page
// that is all one millisecond is read again, twice as large, until it holds
// that millisecond whole.
func drain[T stored](ctx context.Context, dr *Drainer, op, path, markKey string, deliver func(T)) error {
	m, have, err := dr.readMark(ctx, op, markKey)
	if err != nil {
		dr.outage(ctx, op, "sign-in history not drained", err)
		return err
	}
	// The horizon is read before the first page: every event stamped before
	// it is already visible to every read below.
	horizon := dr.d.Signal.horizon()
	floor := int64(0)
	if have {
		floor = m.Time
	}
	read, err := readFrom[T](ctx, dr, op, path, floor)
	if err != nil {
		dr.outage(ctx, op, "sign-in history not drained", err)
		return err
	}
	known := map[string]bool{}
	for _, id := range m.IDs {
		known[id] = true
	}
	newest := floor
	var fresh []T
	for _, e := range read {
		newest = max(newest, e.ms())
		if !known[e.key()] {
			fresh = append(fresh, e)
		}
	}
	// Oldest first; ties in the order the service returned them.
	slices.SortStableFunc(fresh, func(a, b T) int { return cmp.Compare(a.ms(), b.ms()) })
	for _, e := range fresh {
		deliver(e)
	}
	next := mark{Time: max(floor, min(newest, horizon))}
	for _, e := range read {
		if e.ms() >= next.Time {
			next.IDs = append(next.IDs, e.key())
		}
	}
	if len(fresh) == 0 && next.Time == floor {
		dr.outage(ctx, op, "", nil)
		return nil
	}
	raw, err := json.Marshal(next)
	if err == nil {
		err = dr.d.Marks.Set(ctx, markKey, string(raw))
	}
	if err != nil {
		err = fmt.Errorf("events: store the mark %s: %w", markKey, err)
		dr.outage(ctx, op, "sign-in history not drained", err)
		return err
	}
	dr.outage(ctx, op, "", nil)
	return nil
}

// readFrom reads every stored event stamped at or after from, each once,
// oldest first.
func readFrom[T stored](ctx context.Context, dr *Drainer, op, path string, from int64) ([]T, error) {
	var out []T
	seen := map[string]bool{}
	for size := pageSize; ; {
		var page []T
		q := url.Values{"dateFrom": {strconv.FormatInt(from, 10)}, "direction": {"asc"}, "max": {strconv.Itoa(size)}}
		if _, err := dr.d.Admin.Admin(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &page); err != nil {
			return nil, fmt.Errorf("events: read %s from %d: %w", op, from, err)
		}
		full := len(page) >= size
		last := int64(0)
		for _, e := range page {
			last = max(last, e.ms())
		}
		if full && slices.IndexFunc(page, func(e T) bool { return e.ms() != last }) < 0 {
			// The whole page is one millisecond: read it again, larger.
			size *= 2
			continue
		}
		for _, e := range page {
			if full && e.ms() == last {
				continue // read whole by the next query, which starts there
			}
			if k := e.key(); !seen[k] {
				seen[k] = true
				out = append(out, e)
			}
		}
		if !full {
			return out, nil
		}
		from, size = last, pageSize
	}
}
