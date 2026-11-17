package apprelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// spy records every index and store call in order, and answers from its
// fields.
type spy struct {
	mu      sync.Mutex
	calls   []string
	app     *apps.App
	getErr  error
	granted bool
	store   error
	index   error
	value   string
	// noKey makes HasTransitKey answer that the app has no such key.
	noKey bool
}

func (s *spy) note(c string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, c)
}

func (s *spy) Get(context.Context, string) (*apps.App, error) { return s.app, s.getErr }
func (s *spy) Granted(*apps.App) bool                         { return s.granted }
func (s *spy) RecordRuntimeSecret(_ context.Context, _, name string) error {
	s.note("record " + name)
	return s.index
}
func (s *spy) ForgetRuntimeSecret(_ context.Context, _, name string) error {
	s.note("forget " + name)
	return s.index
}
func (s *spy) Read(_ context.Context, a secrets.Actor, r secrets.Ref) (secrets.Secret, error) {
	s.note("read " + r.String())
	if s.store != nil {
		return secrets.Secret{}, s.store
	}
	return secrets.Secret{Value: secret.New([]byte(s.value)), Version: 1}, nil
}
func (s *spy) Create(_ context.Context, _ secrets.Actor, r secrets.Ref, _ secret.Value) (int, error) {
	s.note("create " + r.String())
	return 1, s.store
}
func (s *spy) Replace(_ context.Context, _ secrets.Actor, r secrets.Ref, _ secret.Value) (int, error) {
	s.note("replace " + r.String())
	return 2, s.store
}
func (s *spy) Delete(_ context.Context, _ secrets.Actor, r secrets.Ref) error {
	s.note("delete " + r.String())
	return s.store
}

func (s *spy) RecordTransitKey(_ context.Context, _, name string) error {
	s.note("record key " + name)
	return s.index
}
func (s *spy) ForgetTransitKey(_ context.Context, _, name string) error {
	s.note("forget key " + name)
	return s.index
}
func (s *spy) HasTransitKey(_ context.Context, _, name string) (bool, error) {
	s.note("has key " + name)
	return !s.noKey, s.index
}
func (s *spy) CreateKey(_ context.Context, _ secrets.Actor, r secrets.Ref) error {
	s.note("create " + r.String())
	return s.store
}
func (s *spy) Encrypt(_ context.Context, _ secrets.Actor, r secrets.Ref, _ secret.Value) (secret.Value, error) {
	s.note("encrypt " + r.String())
	if s.store != nil {
		return secret.Value{}, s.store
	}
	return secret.New([]byte(s.value)), nil
}
func (s *spy) Decrypt(_ context.Context, _ secrets.Actor, r secrets.Ref, _ secret.Value) (secret.Value, error) {
	s.note("decrypt " + r.String())
	if s.store != nil {
		return secret.Value{}, s.store
	}
	return secret.New([]byte(s.value)), nil
}
func (s *spy) DestroyKey(_ context.Context, _ secrets.Actor, r secrets.Ref) error {
	s.note("destroy " + r.String())
	return s.store
}

func (s *spy) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func newSpyService(t *testing.T, s *spy) *Service {
	t.Helper()
	svc, err := NewService(ServiceDeps{Apps: s, Grants: s, Index: s, Secrets: s})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func call(t *testing.T, op, name string) Call {
	t.Helper()
	ref, err := secrets.AppRuntimeSecret(appA, name)
	if err != nil {
		t.Fatal(err)
	}
	return Call{Node: nodeN, AppID: appA, Op: op, Ref: ref, Name: name, Value: secret.New([]byte("v"))}
}

// TC-1081-17: an app that is not granted (or does not exist, or is not on the
// calling node) is refused before any index or store call. Create records
// the row before the store create, and a failed create leaves it. Delete
// deletes the store entry before forgetting the row, and a failed delete
// leaves it. Read touches no index.
func TestService_OrderAndGrant(t *testing.T) {
	ref := "apps/" + appA + "/_runtime/k"
	storeDown := errors.New("store down")
	for _, tc := range []struct {
		name    string
		s       *spy
		op      string
		want    []string
		wantErr error
	}{
		{"not granted", &spy{app: appOn(appA, nodeN)}, proto.AppSecretCreate, nil, ErrNotGranted},
		{"no app", &spy{granted: true}, proto.AppSecretCreate, nil, ErrNoApp},
		{"wrong node", &spy{app: appOn(appA, nodeM), granted: true}, proto.AppSecretCreate, nil, ErrWrongNode},
		{"create", &spy{app: appOn(appA, nodeN), granted: true}, proto.AppSecretCreate, []string{"record k", "create " + ref}, nil},
		{"failed create leaves the row", &spy{app: appOn(appA, nodeN), granted: true, store: storeDown}, proto.AppSecretCreate, []string{"record k", "create " + ref}, storeDown},
		{"delete", &spy{app: appOn(appA, nodeN), granted: true}, proto.AppSecretDelete, []string{"delete " + ref, "forget k"}, nil},
		{"failed delete leaves the row", &spy{app: appOn(appA, nodeN), granted: true, store: storeDown}, proto.AppSecretDelete, []string{"delete " + ref}, storeDown},
		{"read touches no index", &spy{app: appOn(appA, nodeN), granted: true}, proto.AppSecretRead, []string{"read " + ref}, nil},
		{"replace touches no index", &spy{app: appOn(appA, nodeN), granted: true}, proto.AppSecretReplace, []string{"replace " + ref}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.s
			v, err := newSpyService(t, s).Do(t.Context(), call(t, tc.op, "k"))
			v.Destroy()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Do = %v, want %v", err, tc.wantErr)
			}
			if got := s.seen(); !slices.Equal(got, tc.want) {
				t.Errorf("calls = %v, want %v", got, tc.want)
			}
		})
	}
}

// capture is a Publisher that records what it was asked to publish.
type capture struct {
	mu   sync.Mutex
	subj []string
	data [][]byte
}

func (c *capture) Publish(subj string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subj = append(c.subj, subj)
	c.data = append(c.data, data)
	return nil
}

func (c *capture) reply(t *testing.T) proto.AppSecretReply {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) != 1 {
		t.Fatalf("published %d replies, want 1", len(c.data))
	}
	var r proto.AppSecretReply
	if err := json.Unmarshal(c.data[0], &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// stubCaller records whether it was called and answers with err.
type stubCaller struct {
	n     int
	got   Call
	err   error
	value string
}

func (s *stubCaller) Do(_ context.Context, c Call) (secret.Value, error) {
	s.n++
	s.got = c
	if s.err != nil {
		return secret.Value{}, s.err
	}
	return secret.New([]byte(s.value)), nil
}

func newTestHandler(t *testing.T, c Caller) (*Handler, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	n := 0
	h, err := NewHandler(HandlerDeps{Service: c, Log: log, IDs: func() string { n++; return fmt.Sprintf("CID%d", n) }})
	if err != nil {
		t.Fatal(err)
	}
	return h, rec
}

func body(op, appID, name, value string) []byte {
	b, _ := json.Marshal(proto.AppSecretCall{AppID: appID, Op: op, Name: name, Value: value})
	return b
}

// TC-1081-15: a reply subject on another node's lane, the shared inbox or
// none is refused with nothing published and the service not called; a
// malformed call is answered invalid with a correlation id and the service
// not called; the node comes from the subject, never the body.
func TestHandler_ParsesAtTheBoundary(t *testing.T) {
	subj := proto.AppSecretCallSubject(nodeN)
	good := proto.AppSecretReplyPrefix(nodeN) + "tok"
	for _, reply := range []string{proto.AppSecretReplyPrefix(nodeM) + "tok", "_INBOX.x", "", proto.AppSecretReplyPrefix(nodeN), proto.AppSecretReplyPrefix(nodeN) + "*"} {
		stub := &stubCaller{}
		h, rec := newTestHandler(t, stub)
		pub := &capture{}
		h.Handle(t.Context(), pub, subj, reply, body(proto.AppSecretRead, appA, "k", ""))
		if len(pub.subj) != 0 || stub.n != 0 {
			t.Errorf("reply %q: published %v, service called %d times; want neither", reply, pub.subj, stub.n)
		}
		if got := rec.Matching(slog.LevelWarn, "reply subject"); len(got) != 1 {
			t.Errorf("reply %q: %d reply_refused WARN records, want 1", reply, len(got))
		}
	}
	big := strings.Repeat("x", proto.AppRelayMaxValueBytes+1)
	for name, data := range map[string][]byte{
		"unknown op":      body("list", appA, "k", ""),
		"lowercase id":    body(proto.AppSecretRead, strings.ToLower(appA), "k", ""),
		"non-ULID id":     body(proto.AppSecretRead, "not-an-app", "k", ""),
		"bad name":        body(proto.AppSecretRead, appA, "_x", ""),
		"oversized value": body(proto.AppSecretCreate, appA, "k", big),
		"malformed JSON":  []byte("{"),
	} {
		stub := &stubCaller{}
		h, _ := newTestHandler(t, stub)
		pub := &capture{}
		h.Handle(t.Context(), pub, subj, good, data)
		r := pub.reply(t)
		if r.Code != proto.AppSecretInvalid || r.CorrelationID == "" || stub.n != 0 {
			t.Errorf("%s: reply %+v with the service called %d times; want invalid, a correlation id, no call", name, r, stub.n)
		}
		if pub.subj[0] != good {
			t.Errorf("%s: replied on %s, want %s", name, pub.subj[0], good)
		}
	}
	stub := &stubCaller{}
	h, _ := newTestHandler(t, stub)
	h.Handle(t.Context(), &capture{}, subj, good, []byte(`{"appId":"`+appA+`","op":"read","name":"k","node":"`+nodeM+`"}`))
	if stub.got.Node != nodeN || stub.got.AppID != appA {
		t.Errorf("the service got node %q app %q, want %q %q", stub.got.Node, stub.got.AppID, nodeN, appA)
	}
}

// TC-1081-16: each error maps to its code; every reply carries a code, a
// sentence and a correlation id; no message carries store text or the value;
// refusals and store failures are logged with their fields, never the value.
func TestHandler_ErrorCodes(t *testing.T) {
	const value = "sentinel-value-1081-16"
	subj := proto.AppSecretCallSubject(nodeN)
	reply := proto.AppSecretReplyPrefix(nodeN) + "tok"
	storeText := errors.New("bao: 500 internal path rasputin-secrets/data/x")
	for _, tc := range []struct {
		name  string
		err   error
		code  string
		level slog.Level
		event string
	}{
		{"not found", fmt.Errorf("x: %w", secretstore.ErrNotFound), proto.AppSecretNotFound, 0, ""},
		{"exists", fmt.Errorf("x: %w", secrets.ErrExists), proto.AppSecretExists, 0, ""},
		{"conflict", fmt.Errorf("x: %w", secrets.ErrConflict), proto.AppSecretConflict, 0, ""},
		{"forbidden", fmt.Errorf("x: %w", secrets.ErrForbidden), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"no app", fmt.Errorf("x: %w", ErrNoApp), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"not granted", fmt.Errorf("x: %w", ErrNotGranted), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"invalid ref", fmt.Errorf("x: %w", secrets.ErrInvalidRef), proto.AppSecretInvalid, slog.LevelWarn, "apprelay.refused"},
		{"invalid value", fmt.Errorf("x: %w", secretstore.ErrInvalidValue), proto.AppSecretInvalid, slog.LevelWarn, "apprelay.refused"},
		{"store failure", fmt.Errorf("%w: %w", secretstore.ErrUnreachable, storeText), proto.AppSecretUnavailable, slog.LevelError, "apprelay.store_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, rec := newTestHandler(t, &stubCaller{err: tc.err})
			pub := &capture{}
			h.Handle(t.Context(), pub, subj, reply, body(proto.AppSecretCreate, appA, "k", value))
			r := pub.reply(t)
			if r.Code != tc.code || r.CorrelationID == "" || r.Message == "" || !strings.HasSuffix(r.Message, ".") {
				t.Errorf("reply %+v, want code %s with a sentence and a correlation id", r, tc.code)
			}
			if strings.Contains(r.Message, "bao") || strings.Contains(r.Message, value) || r.Value != "" {
				t.Errorf("the reply leaks store text or the value: %+v", r)
			}
			if strings.Contains(rec.Text(), value) {
				t.Error("the value reached a log record")
			}
			if tc.event == "" {
				if n := len(rec.Records()); n != 0 {
					t.Errorf("%d records for an ordinary outcome, want none", n)
				}
				return
			}
			recs := rec.AtLevel(tc.level)
			if len(recs) != 1 {
				t.Fatalf("%d records at %v, want 1", len(recs), tc.level)
			}
			for k, want := range map[string]string{"event": tc.event, "node": nodeN, "app_id": appA, "op": "create", "name": "k", "correlation_id": r.CorrelationID} {
				if got, _ := logkittest.Attr(recs[0], k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			field := "reason"
			if tc.event == "apprelay.store_failed" {
				field = "err"
			}
			if got, ok := logkittest.Attr(recs[0], field); !ok || got == "" {
				t.Errorf("the record has no %s", field)
			}
		})
	}
	t.Run("ok read carries the value", func(t *testing.T) {
		h, _ := newTestHandler(t, &stubCaller{value: value})
		pub := &capture{}
		h.Handle(t.Context(), pub, subj, reply, body(proto.AppSecretRead, appA, "k", ""))
		if r := pub.reply(t); r.Code != proto.AppSecretOK || r.Value != value || r.CorrelationID == "" {
			t.Errorf("reply %+v, want ok with the value", r)
		}
	})
}

// The handler is subscribed on the filter every node's calls arrive under.
func TestHandler_SubscribesAndReplies(t *testing.T) {
	nc := startNATS(t)
	h, _ := newTestHandler(t, &stubCaller{value: "v"})
	if _, err := h.Subscribe(nc); err != nil {
		t.Fatal(err)
	}
	reply := proto.AppSecretReplyPrefix(nodeN) + "tok"
	sub, err := nc.SubscribeSync(reply)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.PublishRequest(proto.AppSecretCallSubject(nodeN), reply, body(proto.AppSecretRead, appA, "k", "")); err != nil {
		t.Fatal(err)
	}
	m, err := sub.NextMsgWithContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var r proto.AppSecretReply
	if err := json.Unmarshal(m.Data, &r); err != nil || r.Code != proto.AppSecretOK {
		t.Fatalf("reply %s, %v", m.Data, err)
	}
}
