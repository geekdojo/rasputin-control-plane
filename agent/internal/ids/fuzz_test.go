package ids

import (
	"testing"
	"time"
)

// FuzzParseAlertFast fuzzes the Snort alert_fast line parser. Alert lines come
// from the IDS log tailer — semi-trusted, but malformed/adversarial lines
// (partial matches that reach the field extractors: timestamp, addr:port)
// must never panic. Step 5, Go-native fuzzing of untrusted-input parsers.
func FuzzParseAlertFast(f *testing.F) {
	f.Add("")
	f.Add("not an alert line")
	f.Add("11/20-14:30:00.123456  [**] [1:1000:1] some msg [**] [Classification: Misc] [Priority: 2] {TCP} 1.2.3.4:80 -> 5.6.7.8:443")
	f.Add("11/20-14:30:00.123456  [**] [1:1000:1] arp [**] {ARP} 1.2.3.4 -> 5.6.7.8")
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	f.Fuzz(func(t *testing.T, line string) {
		_, _, _ = ParseAlertFast("node-fuzz", line, now)
	})
}
