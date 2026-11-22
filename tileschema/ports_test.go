package tileschema

import (
	"reflect"
	"testing"
)

// TC-1091-11: the catalog publisher's port grammar, moved here unchanged,
// reads the two short forms and nothing else.
func TestParsePortEntry(t *testing.T) {
	for _, c := range []struct {
		entry any
		want  PortBinding
		ok    bool
	}{
		{"8096:8096", PortBinding{HostIP: "", Published: 8096}, true},
		{"127.0.0.1:8085:8080", PortBinding{HostIP: "127.0.0.1", Published: 8085}, true},
		{"1:65535", PortBinding{HostIP: "", Published: 1}, true},
		{"65535:1", PortBinding{HostIP: "", Published: 65535}, true},

		{"8000-8010:8000-8010", PortBinding{}, false},
		{map[string]any{"target": 80, "published": 8080}, PortBinding{}, false},
		{"${PORT}:80", PortBinding{}, false},
		{"[::1]:8096:8096", PortBinding{}, false},
		{"8096:8096/udp", PortBinding{}, false},
		{8096, PortBinding{}, false},
		{"8096", PortBinding{}, false},
		{"localhost:8096:8096", PortBinding{}, false},
		{"70000:80", PortBinding{}, false},
		{"0:80", PortBinding{}, false},
		{"80:65536", PortBinding{}, false},
	} {
		got, ok := ParsePortEntry(c.entry)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParsePortEntry(%#v) = %+v, %v; want %+v, %v", c.entry, got, ok, c.want, c.ok)
		}
	}
}
