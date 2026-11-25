package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// fakeAdmin answers from a table keyed on "METHOD path" and records each
// call.
type fakeAdmin struct {
	calls   []string
	answers map[string]any
	fail    map[string]error
}

func (f *fakeAdmin) Admin(_ context.Context, method, path string, _, out any) (idclient.Response, error) {
	k := method + " " + path
	f.calls = append(f.calls, k)
	if err, ok := f.fail[k]; ok {
		return idclient.Response{}, err
	}
	if a, ok := f.answers[k]; ok && out != nil {
		b, _ := json.Marshal(a)
		_ = json.Unmarshal(b, out)
	}
	return idclient.Response{Status: http.StatusNoContent}, nil
}

const user = "/admin/realms/rasputin/users/u-1"

func clientsPage(first int) string {
	return fmt.Sprintf("GET /admin/realms/rasputin/clients?first=%d&max=%d", first, clientPage)
}

func ids(prefix string, n int) []map[string]string {
	out := make([]map[string]string, n)
	for i := range out {
		out[i] = map[string]string{"id": fmt.Sprintf("%s%d", prefix, i)}
	}
	return out
}

// EndAll is one POST to the account's logout, and its error is wrapped.
func TestEndAll(t *testing.T) {
	f := &fakeAdmin{}
	if err := (Ender{Admin: f}).EndAll(t.Context(), "u-1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls, []string{"POST " + user + "/logout"}) {
		t.Errorf("calls %v", f.calls)
	}
	f = &fakeAdmin{fail: map[string]error{"POST " + user + "/logout": idclient.ErrUnreachable}}
	if err := (Ender{Admin: f}).EndAll(t.Context(), "u-1"); !errors.Is(err, idclient.ErrUnreachable) ||
		!strings.Contains(err.Error(), "end online sessions") {
		t.Errorf("err %v", err)
	}
	if err := (Ender{Admin: f}).EndAll(t.Context(), ""); err == nil {
		t.Error("an empty id was accepted")
	}
}

// EndOffline reads every client, a page at a time, reads the account's
// offline sessions at each, and deletes each session once: a session two
// clients name is deleted once, and one already gone counts as ended.
func TestEndOffline(t *testing.T) {
	page2 := ids("c", 2) // a short second page ends the read
	f := &fakeAdmin{answers: map[string]any{
		clientsPage(0):                         ids("x", clientPage),
		clientsPage(clientPage):                page2,
		"GET " + user + "/offline-sessions/c0": []map[string]string{{"id": "s1"}, {"id": "s2"}},
		"GET " + user + "/offline-sessions/c1": []map[string]string{{"id": "s2"}, {"id": "s3"}},
	}, fail: map[string]error{"DELETE /admin/realms/rasputin/sessions/s3?isOffline=true": idclient.ErrNotFound}}
	n, err := (Ender{Admin: f}).EndOffline(t.Context(), "u-1")
	if err != nil || n != 3 {
		t.Fatalf("EndOffline = %d, %v; want 3", n, err)
	}
	var deletes []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "DELETE") {
			deletes = append(deletes, c)
		}
	}
	want := []string{
		"DELETE /admin/realms/rasputin/sessions/s1?isOffline=true",
		"DELETE /admin/realms/rasputin/sessions/s2?isOffline=true",
		"DELETE /admin/realms/rasputin/sessions/s3?isOffline=true",
	}
	if !slices.Equal(deletes, want) {
		t.Errorf("deletes %v", deletes)
	}
	if reads := slices.IndexFunc(f.calls, func(c string) bool { return c == "GET "+user+"/offline-sessions/x99" }); reads < 0 {
		t.Error("the first page's last client was not read")
	}
}

// Each failing call is returned wrapped, naming the offline leg.
func TestEndOffline_Errors(t *testing.T) {
	for _, k := range []string{
		clientsPage(0),
		"GET " + user + "/offline-sessions/c0",
		"DELETE /admin/realms/rasputin/sessions/s1?isOffline=true",
	} {
		f := &fakeAdmin{answers: map[string]any{
			clientsPage(0):                         ids("c", 1),
			"GET " + user + "/offline-sessions/c0": []map[string]string{{"id": "s1"}},
		}, fail: map[string]error{k: idclient.ErrForbidden}}
		if _, err := (Ender{Admin: f}).EndOffline(t.Context(), "u-1"); !errors.Is(err, idclient.ErrForbidden) ||
			!strings.Contains(err.Error(), "end offline sessions") {
			t.Errorf("%s failing: %v", k, err)
		}
	}
	if _, err := (Ender{Admin: &fakeAdmin{}}).EndOffline(t.Context(), ""); err == nil {
		t.Error("an empty id was accepted")
	}
}
