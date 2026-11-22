package tailscale

import (
	"slices"
	"testing"
)

// TC-984-07: upArgs writes both settings out in every case, with the value
// spelled, so a false reaches `tailscale up` instead of falling back to its
// accept-dns=true default; the order of the other arguments is unchanged.
func TestUpArgs_AlwaysSendsBothSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   EnrollInput
		want []string
	}{
		{
			name: "control plane",
			in:   EnrollInput{LoginServer: "https://127.0.0.1:18080", AuthKey: "k-cp", Hostname: "cp1"},
			want: []string{"up", "--login-server=https://127.0.0.1:18080", "--auth-key=k-cp", "--reset",
				"--hostname=cp1", "--accept-dns=false", "--accept-routes=false"},
		},
		{
			name: "compute",
			in: EnrollInput{LoginServer: "https://bench.local:18080", AuthKey: "k-c", Hostname: "c01",
				AdvertiseRoutes: []string{"10.0.0.0/24"}, AcceptDNS: true, AcceptRoutes: true},
			want: []string{"up", "--login-server=https://bench.local:18080", "--auth-key=k-c", "--reset",
				"--hostname=c01", "--advertise-routes=10.0.0.0/24", "--accept-dns=true", "--accept-routes=true"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := upArgs(tc.in); !slices.Equal(got, tc.want) {
				t.Errorf("upArgs = %q\nwant      %q", got, tc.want)
			}
		})
	}
}
