package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeAdmin serves stored events as Keycloak 26.8.2's events endpoints do:
// filtered by dateFrom (inclusive), ordered by time alone in the direction
// asked (newest first by default), then cut by first and max. With
// shuffleTies, each read orders the events of one millisecond differently,
// as PostgreSQL may for an ORDER BY with no tie-breaker.
type fakeAdmin struct {
	mu    sync.Mutex
	user  []userRep
	admin []adminRep
	// failIf fails a user-events read whose query it matches, while
	// failures is above zero.
	failIf      func(q url.Values) bool
	failures    int
	shuffleTies bool
	reads       int
	calls       []string
}

func (f *fakeAdmin) Admin(_ context.Context, method, path string, _, out any) (idclient.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method+" "+path)
	f.reads++
	p, raw, _ := strings.Cut(path, "?")
	q, _ := url.ParseQuery(raw)
	if strings.HasSuffix(p, "/events") && f.failures > 0 && f.failIf != nil && f.failIf(q) {
		f.failures--
		return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Kind: idclient.ErrUnreachable}
	}
	var b []byte
	switch {
	case strings.HasSuffix(p, "/admin-events"):
		b, _ = json.Marshal(query(f.admin, q, f.shuffleTies && f.reads%2 == 1))
	case strings.HasSuffix(p, "/events"):
		b, _ = json.Marshal(query(f.user, q, f.shuffleTies && f.reads%2 == 1))
	default:
		return idclient.Response{}, errors.New("unexpected path " + path)
	}
	return idclient.Response{Status: 200}, json.Unmarshal(b, out)
}

// query is one events query over all: dateFrom, direction, first and max,
// with each millisecond's events reversed when flip is set.
func query[T stored](all []T, q url.Values, flip bool) []T {
	var out []T
	from, _ := strconv.ParseInt(q.Get("dateFrom"), 10, 64)
	for _, e := range all {
		if q.Get("dateFrom") == "" || e.ms() >= from {
			out = append(out, e)
		}
	}
	asc := q.Get("direction") == "asc"
	sort.SliceStable(out, func(i, j int) bool {
		if asc {
			return out[i].ms() < out[j].ms()
		}
		return out[i].ms() > out[j].ms()
	})
	if flip {
		for i := 0; i < len(out); {
			j := i
			for j < len(out) && out[j].ms() == out[i].ms() {
				j++
			}
			slices.Reverse(out[i:j])
			i = j
		}
	}
	first, _ := strconv.Atoi(q.Get("first"))
	max := 100
	if m := q.Get("max"); m != "" {
		max, _ = strconv.Atoi(m)
	}
	if first >= len(out) {
		return []T{}
	}
	return out[first:min(first+max, len(out))]
}

func (f *fakeAdmin) add(events ...userRep) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user = append(f.user, events...)
}

type fakeMarks struct {
	mu             sync.Mutex
	m              map[string]string
	getErr, setErr error
	sets           int
}

func (f *fakeMarks) Get(_ context.Context, k string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[k], f.getErr
}

func (f *fakeMarks) Set(_ context.Context, k, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.sets++
	f.m[k] = v
	return nil
}

type sinkRec struct {
	mu     sync.Mutex
	got    []string
	admins []string
	starts []uint64
	ends   []uint64
}

func (s *sinkRec) UserEvent(_ context.Context, e UserEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e.ID)
}
func (s *sinkRec) AdminEvent(_ context.Context, e AdminEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admins = append(s.admins, e.ID)
}
func (s *sinkRec) PassStarted(_ context.Context, n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, n)
}
func (s *sinkRec) PassEnded(_ context.Context, n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ends = append(s.ends, n)
}
func (s *sinkRec) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.got...)
}

type rig struct {
	admin *fakeAdmin
	marks *fakeMarks
	sink  *sinkRec
	rec   *logkittest.Recorder
	clock *testClock
	d     *Drainer
}

// testClock is the signal's clock, in milliseconds, set by the test.
type testClock struct{ ms atomic.Int64 }

func (c *testClock) now() time.Time { return time.UnixMilli(c.ms.Load()) }

func newRig(t *testing.T) *rig {
	t.Helper()
	log, rec := logkittest.New()
	r := &rig{admin: &fakeAdmin{}, marks: &fakeMarks{m: map[string]string{}}, sink: &sinkRec{}, rec: rec, clock: &testClock{}}
	// Every test event is stamped before the clock, unless a test sets it.
	r.clock.ms.Store(1 << 40)
	d, err := New(Deps{Admin: r.admin, Marks: r.marks, Signal: NewSignal(r.clock.now), Realm: "rasputin",
		UserSinks: []UserSink{r.sink}, AdminSinks: []AdminSink{r.sink}, PassSinks: []PassSink{r.sink}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.d = d
	return r
}

// ev is a LOGIN_ERROR at ms with id, from a planted address and user.
func ev(id string, ms int64) userRep {
	return userRep{ID: id, Time: ms, Type: "LOGIN_ERROR", ClientID: "rasputin-console", UserID: "user-needle",
		IPAddress: "192.0.2.77", Error: "invalid_user_credentials"}
}

// userWarns counts the drain-failure WARNs for the user stream.
func userWarns(rec *logkittest.Recorder) int {
	n := 0
	for _, w := range rec.Matching(slog.LevelWarn, "sign-in history not drained") {
		if op, _ := logkittest.Attr(w, "op"); op == "events.user" {
			n++
		}
	}
	return n
}

func behind(t *testing.T, d *Drainer) bool {
	t.Helper()
	b, err := d.Behind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TC-985-31: with no mark, the first pass delivers each stored event once,
// oldest first, and stores a mark; a second pass delivers nothing.
func TestDrainer_NoMarkDeliversEverythingOnce(t *testing.T) {
	r := newRig(t)
	r.admin.add(ev("a", 1000), ev("b", 2000), ev("c", 3000))
	r.d.pass(context.Background())
	if got := r.sink.ids(); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("first pass delivered %v, want a b c oldest first", got)
	}
	var m mark
	if err := json.Unmarshal([]byte(r.marks.m[UserMarkKey]), &m); err != nil || m.Time != 3000 || !reflect.DeepEqual(m.IDs, []string{"c"}) {
		t.Fatalf("stored mark %q (%v), want time 3000 ids [c]", r.marks.m[UserMarkKey], err)
	}
	r.d.pass(context.Background())
	if got := r.sink.ids(); len(got) != 3 {
		t.Fatalf("a second pass delivered again: %v", got)
	}
	if behind(t, r.d) {
		t.Error("a good pass left behind set")
	}
}

// TC-985-31: paging newest first back to the mark over more than one page,
// with several events in the mark's millisecond, delivers each new event
// once.
func TestDrainer_PagesBackToTheMarkWithTies(t *testing.T) {
	r := newRig(t)
	r.admin.add(ev("t1", 5000), ev("t2", 5000))
	r.d.pass(context.Background())
	// 250 more events, three of them in the mark's millisecond, and many at
	// one later millisecond across a page boundary.
	var more []userRep
	more = append(more, ev("t3", 5000))
	for i := range 150 {
		more = append(more, ev(fmt.Sprintf("s%03d", i), 6000))
	}
	for i := range 99 {
		more = append(more, ev(fmt.Sprintf("u%03d", i), int64(7000+i)))
	}
	r.admin.add(more...)
	r.d.pass(context.Background())
	got := r.sink.ids()
	seen := map[string]int{}
	for _, id := range got {
		seen[id]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("event %s delivered %d times", id, n)
		}
	}
	if len(got) != 2+len(more) {
		t.Fatalf("delivered %d events, want %d", len(got), 2+len(more))
	}
	if got[2] != "t3" || got[len(got)-1] != "u098" {
		t.Errorf("second pass order starts %s and ends %s, want t3 then ... u098", got[2], got[len(got)-1])
	}
}

// TC-985-31: a failure on an older page delivers nothing and leaves the mark
// unchanged; the next pass delivers every missed event once; behind is set
// with one WARN per outage and cleared by the good pass.
func TestDrainer_FailedPageDeliversNothing(t *testing.T) {
	r := newRig(t)
	r.admin.add(ev("first", 1000))
	r.d.pass(context.Background())
	before := r.marks.m[UserMarkKey]
	for i := range 150 {
		r.admin.add(ev(fmt.Sprintf("n%03d", i), int64(2000+i)))
	}
	// The second read of each pass, the one after the first page, fails.
	r.admin.failIf = func(q url.Values) bool { return q.Get("dateFrom") != "1000" }
	r.admin.failures = 2
	r.d.pass(context.Background())
	r.d.pass(context.Background())
	if got := r.sink.ids(); len(got) != 1 {
		t.Fatalf("failed passes delivered %d events, want only the first pass's 1", len(got))
	}
	if r.marks.m[UserMarkKey] != before {
		t.Fatalf("a failed pass moved the mark from %q to %q", before, r.marks.m[UserMarkKey])
	}
	if !behind(t, r.d) {
		t.Fatal("a failed pass left behind clear")
	}
	if n := userWarns(r.rec); n != 1 {
		t.Errorf("%d WARN records for the user stream over two failed passes, want 1", n)
	}
	r.d.pass(context.Background())
	if got := r.sink.ids(); len(got) != 151 {
		t.Fatalf("the good pass delivered %d in total, want 151", len(got))
	}
	if behind(t, r.d) {
		t.Error("the good pass left behind set")
	}
}

// TC-985-31: a malformed mark is one WARN and read as absent.
func TestDrainer_MalformedMark(t *testing.T) {
	r := newRig(t)
	r.marks.m[UserMarkKey] = "{not json"
	r.admin.add(ev("a", 1000))
	r.d.pass(context.Background())
	r.marks.m[UserMarkKey] = "{also not json"
	r.d.pass(context.Background())
	if got := r.sink.ids(); !reflect.DeepEqual(got, []string{"a", "a"}) {
		t.Fatalf("delivered %v, want a once per pass (the mark read as absent each time)", got)
	}
	if warns := r.rec.Matching(slog.LevelWarn, "mark unreadable"); len(warns) != 1 {
		t.Errorf("%d WARN records for a malformed mark twice, want 1", len(warns))
	}
	if behind(t, r.d) {
		t.Error("a malformed mark set behind; it is read as absent")
	}
}

// TC-985-31: a failed Get or Set sets behind with one WARN per outage and
// never overwrites the mark; a later good pass clears behind.
func TestDrainer_MarkReadOrWriteFails(t *testing.T) {
	r := newRig(t)
	r.admin.add(ev("a", 1000))
	r.marks.getErr = errors.New("database is locked")
	r.d.pass(context.Background())
	if !behind(t, r.d) || len(r.sink.ids()) != 0 || r.marks.sets != 0 {
		t.Fatalf("a failed Get: behind %v, delivered %v, sets %d; want behind, nothing, no write", behind(t, r.d), r.sink.ids(), r.marks.sets)
	}
	r.marks.getErr = nil
	r.marks.setErr = errors.New("disk full")
	r.d.pass(context.Background())
	r.d.pass(context.Background())
	if !behind(t, r.d) || r.marks.m[UserMarkKey] != "" {
		t.Fatalf("a failed Set: behind %v, mark %q; want behind and no mark", behind(t, r.d), r.marks.m[UserMarkKey])
	}
	if n := userWarns(r.rec); n != 1 {
		t.Errorf("%d WARN records for the user stream over one outage, want 1", n)
	}
	r.marks.setErr = nil
	r.d.pass(context.Background())
	if behind(t, r.d) || r.marks.m[UserMarkKey] == "" {
		t.Error("a good pass after the outage left behind set or no mark")
	}
}

// TC-985-31: no event body, user id or address reaches a record.
func TestDrainer_LogsNoEventDetail(t *testing.T) {
	r := newRig(t)
	r.admin.add(ev("a", 1000))
	r.admin.failIf = func(url.Values) bool { return true }
	r.admin.failures = 1
	r.d.pass(context.Background())
	r.marks.m[UserMarkKey] = "{bad"
	r.d.pass(context.Background())
	text := r.rec.Text()
	for _, needle := range []string{"user-needle", "192.0.2.77", "invalid_user_credentials"} {
		if strings.Contains(text, needle) {
			t.Errorf("a record holds %q:\n%s", needle, text)
		}
	}
}

// TC-985-31 and TC-985-32: Run drains only after MarkDirty, and marks made
// while a pass runs coalesce into one more pass.
func TestDrainer_RunsOnMarksAndCoalesces(t *testing.T) {
	r := newRig(t)
	ends := &endSink{ch: make(chan uint64, 8)}
	r.d.d.PassSinks = append(r.d.d.PassSinks, ends)
	// entered holds one signal, so the first call's is never dropped
	// whichever of the pass and the test gets there first.
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	r.d.d.Admin = &gatedAdmin{inner: r.admin, entered: entered, release: release}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.d.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	if n := r.d.Pass(); n != 0 {
		t.Fatalf("Run started %d passes before any mark", n)
	}
	r.d.MarkDirty()
	<-entered // the first pass is reading, held
	for range 5 {
		r.d.MarkDirty()
	}
	close(release)
	if got := []uint64{<-ends.ch, <-ends.ch}; !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("pass ends %v, want [1 2]", got)
	}
	// The five marks made one pass: none is pending.
	if len(r.d.d.Signal.ch) != 0 {
		t.Fatal("a mark is still pending after the coalesced pass")
	}
	select {
	case n := <-ends.ch:
		t.Fatalf("a third pass %d ran", n)
	default:
	}
}

// endSink reports each pass end on ch.
type endSink struct{ ch chan uint64 }

func (endSink) PassStarted(context.Context, uint64) {}

func (e *endSink) PassEnded(_ context.Context, n uint64) { e.ch <- n }

// gatedAdmin holds the first call until release, and signals entered on
// every call.
type gatedAdmin struct {
	inner   Admin
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedAdmin) Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	g.once.Do(func() { <-g.release })
	return g.inner.Admin(ctx, method, path, in, out)
}

// The admin stream is drained and marked too, with its own key.
func TestDrainer_AdminEvents(t *testing.T) {
	r := newRig(t)
	r.admin.admin = []adminRep{{ID: "x", Time: 10, OperationType: "UPDATE"}, {ID: "y", Time: 20, OperationType: "CREATE"}}
	r.d.pass(context.Background())
	if !reflect.DeepEqual(r.sink.admins, []string{"x", "y"}) || r.marks.m[AdminMarkKey] == "" {
		t.Fatalf("admin events %v, mark %q", r.sink.admins, r.marks.m[AdminMarkKey])
	}
}

// An event stored with no id gets a synthetic key that holds no field in
// the clear, and still dedupes.
func TestDrainer_EventWithoutID(t *testing.T) {
	r := newRig(t)
	e := ev("", 1000)
	r.admin.add(e)
	r.d.pass(context.Background())
	r.d.pass(context.Background())
	got := r.sink.ids()
	if len(got) != 1 || !strings.HasPrefix(got[0], "h:") || strings.Contains(got[0], "192.0.2.77") {
		t.Fatalf("delivered %v, want one synthetic key", got)
	}
	if ip := e.event().IP.String(); ip != "192.0.2.77" {
		t.Errorf("the event's address %s", ip)
	}
	if bad := (userRep{IPAddress: "not an address"}).event().IP; bad.IsValid() {
		t.Errorf("an unparsable address read as %s", bad)
	}
}

func TestNew_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	ok := Deps{Admin: &fakeAdmin{}, Marks: &fakeMarks{}, Signal: NewSignal(time.Now), Realm: "rasputin", Log: log}
	for name, mut := range map[string]func(*Deps){
		"Admin": func(d *Deps) { d.Admin = nil }, "Marks": func(d *Deps) { d.Marks = nil },
		"Signal": func(d *Deps) { d.Signal = nil }, "Realm": func(d *Deps) { d.Realm = "" }, "Log": func(d *Deps) { d.Log = nil },
	} {
		d := ok
		mut(&d)
		if _, err := New(d); err == nil {
			t.Errorf("New with no %s succeeded", name)
		}
	}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
}

// offsetRead is the read the drain no longer makes: newest first, paged by
// first and max.
func offsetRead(t *testing.T, a *fakeAdmin) map[string]int {
	t.Helper()
	got := map[string]int{}
	for first := 0; ; first += pageSize {
		var page []userRep
		q := url.Values{"first": {strconv.Itoa(first)}, "max": {strconv.Itoa(pageSize)}}
		if _, err := a.Admin(context.Background(), "GET", "/admin/realms/rasputin/events?"+q.Encode(), nil, &page); err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			got[e.ID]++
		}
		if len(page) < pageSize {
			return got
		}
	}
}

// TC-985-44's loss, reproduced (F-985-25): the service orders events by time
// with no tie-breaker, so each read may order one millisecond's events
// differently. Offset pages then drop an event between them; the drain's
// reads by time deliver each event once.
func TestDrainer_TiesOrderedDifferentlyPerRead(t *testing.T) {
	r := newRig(t)
	r.admin.shuffleTies = true
	var all []userRep
	for i := range 60 {
		all = append(all, ev(fmt.Sprintf("a%03d", i), int64(1000+i)))
	}
	// 80 events in one millisecond, across the first page boundary of a
	// newest-first read (positions 60 to 139), and 60 newer.
	for i := range 80 {
		all = append(all, ev(fmt.Sprintf("t%03d", i), 2000))
	}
	for i := range 60 {
		all = append(all, ev(fmt.Sprintf("z%03d", i), int64(3000+i)))
	}
	r.admin.add(all...)
	if got := offsetRead(t, r.admin); len(got) == len(all) {
		t.Fatalf("the fake's offset pages returned all %d events; it does not model the order without a tie-breaker", len(all))
	}
	r.d.pass(context.Background())
	seen := map[string]int{}
	for _, id := range r.sink.ids() {
		seen[id]++
	}
	for _, e := range all {
		if seen[e.ID] != 1 {
			t.Errorf("event %s delivered %d times, want once", e.ID, seen[e.ID])
		}
	}
	r.admin.add(ev("late", 4000))
	r.d.pass(context.Background())
	if got := r.sink.ids(); len(got) != len(all)+1 || got[len(got)-1] != "late" {
		t.Fatalf("the second pass delivered %d in total ending %q, want %d ending late", len(got), got[len(got)-1], len(all)+1)
	}
}

// F-985-25's other path: an event stamped before one the drain has already
// read, but committed after it, is still delivered once, because the mark
// never passes the start of a request still open.
func TestDrainer_LateCommitBehindTheMark(t *testing.T) {
	r := newRig(t)
	r.clock.ms.Store(5000)
	end := r.d.Begin() // request A begins at 5000
	r.clock.ms.Store(5002)
	r.admin.add(ev("b", 5002)) // request B's event, committed first
	r.d.pass(context.Background())
	var m mark
	if err := json.Unmarshal([]byte(r.marks.m[UserMarkKey]), &m); err != nil || m.Time != 5000 {
		t.Fatalf("mark %q (%v), want its floor held at A's start, 5000", r.marks.m[UserMarkKey], err)
	}
	r.admin.add(ev("a", 5001)) // A's event, stamped before b, committed now
	end()
	r.clock.ms.Store(6000)
	r.d.pass(context.Background())
	if got := r.sink.ids(); !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Fatalf("delivered %v, want b then a, each once", got)
	}
	if err := json.Unmarshal([]byte(r.marks.m[UserMarkKey]), &m); err != nil || m.Time != 5002 || !reflect.DeepEqual(m.IDs, []string{"b"}) {
		t.Fatalf("mark %q (%v), want floor 5002 with ids [b] once nothing is open", r.marks.m[UserMarkKey], err)
	}
	r.d.pass(context.Background())
	if got := r.sink.ids(); len(got) != 2 {
		t.Fatalf("a third pass delivered again: %v", got)
	}
}

// The signal's horizon is the oldest open request's start, or now.
func TestSignal_Horizon(t *testing.T) {
	c := &testClock{}
	c.ms.Store(100)
	s := NewSignal(c.now)
	if h := s.horizon(); h != 100 {
		t.Fatalf("horizon with nothing open %d, want now 100", h)
	}
	endA := s.Begin()
	c.ms.Store(200)
	endB := s.Begin()
	c.ms.Store(300)
	if h := s.horizon(); h != 100 {
		t.Fatalf("horizon %d, want the oldest open start 100", h)
	}
	endA()
	endA()
	if h := s.horizon(); h != 200 {
		t.Fatalf("horizon %d after A ended, want 200", h)
	}
	endB()
	if h := s.horizon(); h != 300 {
		t.Fatalf("horizon %d with nothing open, want now 300", h)
	}
}

// TC-987-38: a user event's credential_type detail is its CredentialType,
// empty without details, and the event key is unchanged by details.
func TestUserEvent_CredentialType(t *testing.T) {
	with := userRep{ID: "e1", Time: 5, Type: "UPDATE_CREDENTIAL", ClientID: "c", UserID: "u",
		Details: map[string]string{"credential_type": "webauthn-passwordless"}}
	without := with
	without.Details = nil
	if got := with.event().CredentialType; got != "webauthn-passwordless" {
		t.Errorf("CredentialType = %q", got)
	}
	if got := without.event().CredentialType; got != "" {
		t.Errorf("CredentialType without details = %q", got)
	}
	noID := with
	noID.ID = ""
	noIDBare := noID
	noIDBare.Details = nil
	if with.key() != without.key() || noID.key() != noIDBare.key() {
		t.Error("details changed the event key")
	}
}

// TC-989-20 (decoder part): an admin event's resourcePath reaches the sinks
// as AdminEvent.ResourcePath, decoded from the service's own JSON field name.
func TestAdminRep_ResourcePathDecoded(t *testing.T) {
	var rep adminRep
	raw := `{"id":"e1","time":42,"operationType":"CREATE","resourceType":"CLIENT_ROLE_MAPPING",` +
		`"resourcePath":"users/0b6e/role-mappings/clients/c-1"}`
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		t.Fatal(err)
	}
	got := rep.event()
	if got.ResourcePath != "users/0b6e/role-mappings/clients/c-1" || got.ResourceType != "CLIENT_ROLE_MAPPING" {
		t.Fatalf("decoded %+v", got)
	}
}
