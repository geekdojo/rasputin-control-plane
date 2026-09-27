package jobs

import "testing"

// Only an explicit ok=false is a refusal. Anything else says nothing either
// way, which is safe because the ack is never the evidence.
func TestRebootRefused(t *testing.T) {
	for _, tc := range []struct {
		reply       string
		wantRefused bool
		wantDetail  string
	}{
		{`{"ok":true,"delaySeconds":3}`, false, ""},
		{`{}`, false, ""},
		{``, false, ""},
		{`not json`, false, ""},
		{`{"ok":false,"detail":"no reboot command"}`, true, "no reboot command"},
		{`{"ok":false}`, true, "the agent gave no reason"},
	} {
		detail, refused := RebootRefused([]byte(tc.reply))
		if refused != tc.wantRefused || detail != tc.wantDetail {
			t.Errorf("RebootRefused(%q) = %q, %v; want %q, %v", tc.reply, detail, refused, tc.wantDetail, tc.wantRefused)
		}
	}
}
