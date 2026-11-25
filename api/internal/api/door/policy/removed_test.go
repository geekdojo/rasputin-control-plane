package policy

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/adminguard"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/removednames"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"

	_ "modernc.org/sqlite"
)

// noneRemoved is a removed-name list holding no name.
type noneRemoved struct{}

func (noneRemoved) Removed(context.Context, string, string) (bool, error) { return false, nil }

// homeNetwork admits registration from 192.0.2.0/24.
type homeNetwork struct{}

func (homeNetwork) Facts(context.Context) (NetworkFacts, error) {
	return NetworkFacts{HomeSubnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, nil
}

type notFull struct{}

func (notFull) Full(context.Context) (bool, error) { return false, nil }

// removedRig is the policy over the real removed-name store in a temp
// rasputin.db, keyed by a real credmac.Key.
type removedRig struct {
	svc    *Service
	store  *removednames.Store
	dbPath string
}

func testMAC(t *testing.T) *credmac.Key {
	t.Helper()
	k, err := credmac.New(secret.New([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newRemovedRig(t *testing.T) *removedRig {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	log, _ := logkittest.New()
	store, err := removednames.OpenStore(t.Context(), dbPath, testMAC(t), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &removedRig{svc: policyWith(t, store), store: store, dbPath: dbPath}
}

func policyWith(t *testing.T, removed RemovedNames) *Service {
	t.Helper()
	th, _ := newThrottle(t)
	svc, err := New(Deps{Table: table(t), Readiness: okReady{}, Throttle: th, AppClients: NoAppClients{},
		Actions: NoActionsIssued{}, Network: homeNetwork{}, Waiting: notFull{}, Removed: removed, Emails: noEmails{}, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

var homePeer = netip.MustParseAddr("192.0.2.7")

// checked is Check, releasing an admitted post's registration slot as the
// door does once the request is done.
func checked(ctx context.Context, svc *Service, r Request) Decision {
	d := svc.Check(ctx, r)
	if d.RegistrationHeld {
		svc.ReleaseRegistration()
	}
	return d
}

// post is a registration form post with form.
func post(form url.Values) Request {
	return Request{Door: Home, Route: RouteRegistration, Method: http.MethodPost, ClientIDs: []string{ConsoleClient},
		Params: map[string][]string{}, Peer: homePeer, Guard: adminguard.Input{Query: url.Values{}, Form: form}}
}

// creates are the account-creation requests with no form: the
// registrations page and an authorization request with prompt=create.
func creates() map[string]Request {
	return map[string]Request{
		"registration GET": {Door: Home, Route: RouteRegistrations, Method: http.MethodGet, ClientIDs: []string{ConsoleClient},
			Params: map[string][]string{"response_type": {"code"}}, Peer: homePeer},
		"prompt=create": {Door: Home, Route: RouteAuth, Method: http.MethodGet, ClientIDs: []string{ConsoleClient},
			Params: map[string][]string{"response_type": {"code"}, "prompt": {"create"}}, Peer: homePeer},
	}
}

const (
	sentencePausedWant  = "Sign-up is paused: Rasputin can't check removed names right now."
	sentenceRemovedWant = "That sign-in name belonged to a removed account and can't be used again."
	sentenceEmailWant   = "Use a different email, or ask an administrator."
)

// TC-991-09: a stored name is refused at registration, whatever its case or
// surrounding space, and as a repeated username value.
func TestRegistration_RemovedName(t *testing.T) {
	r := newRemovedRig(t)
	if err := r.store.Record(t.Context(), "alice", "alice@example.invalid"); err != nil {
		t.Fatal(err)
	}
	for _, names := range [][]string{{"alice"}, {" Alice "}, {"ALICE"}, {"bob", "alice"}} {
		d := checked(t.Context(), r.svc, post(url.Values{"username": names, "email": {"new@example.invalid"}}))
		if d.Allow || d.Status != http.StatusForbidden || d.Reason != "registration_removed_name" || d.Sentence != sentenceRemovedWant {
			t.Errorf("username %q: %+v", names, d)
		}
	}
}

// TC-991-10: a stored email with a new name is refused with the taken-email
// sentence, which doesn't say the address was removed.
func TestRegistration_RemovedEmail(t *testing.T) {
	r := newRemovedRig(t)
	if err := r.store.Record(t.Context(), "alice", "Alice@Example.invalid"); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"alice@example.invalid", "ALICE@EXAMPLE.INVALID"} {
		d := checked(t.Context(), r.svc, post(url.Values{"username": {"carol"}, "email": {email}}))
		if d.Allow || d.Status != http.StatusForbidden {
			t.Fatalf("email %q admitted: %+v", email, d)
		}
		if d.Sentence != sentenceEmailWant {
			t.Errorf("email %q: sentence %q", email, d.Sentence)
		}
		for _, leak := range []string{"removed", "deleted"} {
			if strings.Contains(d.Sentence, leak) {
				t.Errorf("the sentence says %q: %q", leak, d.Sentence)
			}
		}
	}
}

// TC-991-12 (the door's part): a name and email never recorded pass this
// rule. TC-991-14: an empty list admits and raises no alert.
func TestRegistration_UnrecordedAndEmptyAdmit(t *testing.T) {
	r := newRemovedRig(t)
	d := checked(t.Context(), r.svc, post(url.Values{"username": {"dave"}, "email": {"dave@example.invalid"}}))
	if !d.Allow {
		t.Errorf("an empty list refused: %+v", d)
	}
	if a := r.store.Alerts(t.Context(), time.Now()); len(a) != 0 {
		t.Errorf("an empty list raised %+v", a)
	}
	if err := r.store.Record(t.Context(), "erin", ""); err != nil {
		t.Fatal(err)
	}
	if d := checked(t.Context(), r.svc, post(url.Values{"username": {"dave"}, "email": {"dave@example.invalid"}})); !d.Allow {
		t.Errorf("an unrecorded name was refused: %+v", d)
	}
}

// TC-991-13 (the door's part): while the list can't be read, a registration
// post, the registrations page and prompt=create each answer 403
// registration_paused with the sentence; after the repair they admit.
func TestRegistration_PausedWhileUnreadable(t *testing.T) {
	r := newRemovedRig(t)
	db, err := sql.Open("sqlite", r.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO removed_names (name_mac, email_mac) VALUES ('', NULL)`); err != nil {
		t.Fatal(err)
	}
	reqs := creates()
	reqs["registration POST"] = post(url.Values{"username": {"frank"}, "email": {"frank@example.invalid"}})
	for what, req := range reqs {
		d := checked(t.Context(), r.svc, req)
		if d.Allow || d.Status != http.StatusForbidden || d.Reason != ReasonRegistrationPaused || d.Sentence != sentencePausedWant || !d.BackLink {
			t.Errorf("%s while unreadable: %+v", what, d)
		}
	}
	if _, err := db.Exec(`DELETE FROM removed_names WHERE name_mac = ''`); err != nil {
		t.Fatal(err)
	}
	for what, req := range reqs {
		if d := checked(t.Context(), r.svc, req); !d.Allow {
			t.Errorf("%s after the repair: %+v", what, d)
		}
	}
	// Unavailable, wired when the store didn't open, pauses too.
	off := policyWith(t, removednames.Unavailable{Err: sql.ErrConnDone})
	for what, req := range reqs {
		if d := checked(t.Context(), off, req); d.Allow || d.Reason != ReasonRegistrationPaused {
			t.Errorf("%s with no store: %+v", what, d)
		}
	}
}
