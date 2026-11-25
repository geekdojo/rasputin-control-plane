package door

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// F-990-02 at the door: an admitted registration post holds the one
// registration slot only while it is relayed, so posts one after another
// each reach the identity service; a refusal for unreadable facts is one
// WARN door.refuse with reason registration_unknown.
func TestDoor_F990_02_RegistrationSlotReleased(t *testing.T) {
	f := newFixture(t)
	post := req{method: http.MethodPost, target: actions("registration") + "?client_id=" + policy.ConsoleClient,
		form: url.Values{"username": {"new"}}}
	for i := range 3 {
		before := f.up.count()
		w := f.do(Home, post)
		f.wantForwarded(w, before, "registration post "+string(rune('1'+i)))
	}
	f.network.err = errors.New("x")
	w := f.do(Home, post)
	if w.Code != http.StatusForbidden {
		t.Errorf("unreadable facts: %d", w.Code)
	}
	found := false
	for _, r := range f.rec.Records() {
		if reason, _ := logkittest.Attr(r, "refused"); reason == policy.ReasonRegistrationUnknown {
			found = true
			if r.Level != slog.LevelWarn {
				t.Errorf("registration_unknown logged at %v, want WARN", r.Level)
			}
		}
	}
	if !found {
		t.Errorf("no registration_unknown record:\n%s", f.rec.Text())
	}
	f.network.err = nil
	before := f.up.count()
	f.wantForwarded(f.do(Home, post), before, "a post after the refusal")
}
