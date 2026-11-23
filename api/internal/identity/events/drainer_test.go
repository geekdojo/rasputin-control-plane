package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeAdmin serves stored events newest first, paged by first and max, as
// Keycloak's events endpoints do.
type fakeAdmin struct {
	mu    sync.Mutex
	user  []userRep
	admin []adminRep
	// failAt fails a user-events read whose first equals it, once per
	// failures count.
	failAt   int
	failures int
	calls    []string
}

func (f *fakeAdmin) Admin(_ context.Context, method, path string, _, out any) (idclient.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method+" "+path)
	p, raw, _ := strings.Cut(path, "?")
	q, _ := url.ParseQuery(raw)
	first, _ := strconv.Atoi(q.Get("first"))
	max, _ := strconv.Atoi(q.Get("max"))
	if strings.HasSuffix(p, "/events") && f.failures > 0 && first == f.failAt {
		f.failures--
		return idclient.Response{}, &idclient.Error{Op: "admin", Path: path, Kind: idclient.ErrUnreachable}
	}
	var b []byte
	switch {
	case strings.HasSuffix(p, "/admin-events"):
		b, _ = json.Marshal(pageOf(newestFirst(f.admin), first, max))
	case strings.HasSuffix(p, "/events"):
		b, _ = json.Marshal(pageOf(newestFirst(f.user), first, max))
	default:
		return idclient.Response{}, errors.New("unexpected path " + path)
	}
	return idclient.Response{Status: 200}, json.Unmarshal(b, out)
}

func newestFirst[T stored](in []T) []T {
	out := append([]T(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ms() > out[j].ms() })
	return out
}

func pageOf[T any](all []T, first, max int) []T {
	if first >= len(all) {
		return []T{}
	}
	end := min(first+max, len(all))
	return all[first:end]
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
	d     *Drainer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	log, rec := logkittest.New()
	r := &rig{admin: &fakeAdmin{}, marks: &fakeMarks{m: map[string]string{}}, sink: &sinkRec{}, rec: rec}
	d, err := New(Deps{Admin: r.admin, Marks: r.marks, Signal: NewSignal(), Realm: "rasputin",
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
	r.admin.failAt, r.admin.failures = pageSize, 2
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
	r.admin.failAt, r.admin.failures = 0, 1
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
	ok := Deps{Admin: &fakeAdmin{}, Marks: &fakeMarks{}, Signal: NewSignal(), Realm: "rasputin", Log: log}
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
