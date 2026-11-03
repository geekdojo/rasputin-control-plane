package tileschema

import "fmt"

// WebPublishHost is the only host address a tile may publish its web port on.
// The node proxy dials the web port on loopback and is the app's front door;
// a web port bound anywhere else is reachable around it (geekdojo/geekdojo-brain#551).
const WebPublishHost = "127.0.0.1"

// ValidateWebPortBind refuses a tile whose web port is published on any host
// address other than WebPublishHost, or is not published at all.
//
// A tile with no web port passes: there is nothing for the proxy to front.
// A stack on host networking that publishes no binding for the web port
// passes too, because it publishes nothing; it is on its own for networking.
// Ports other than the web port are not checked.
//
// Only the catalog publisher (corpus.BuildBundle) and tilelint call this. The
// control plane's reader never does, so the embedded floor and cached bundles
// signed before the rule existed keep loading.
func ValidateWebPortBind(t Tile, f SafetyFacts) error {
	web := t.WebPort()
	if web == 0 {
		return nil
	}
	published := false
	for _, b := range f.PortBindings {
		if b.Published != web {
			continue
		}
		if b.HostIP != WebPublishHost {
			return fmt.Errorf("web port %d is published on %s, not loopback: write it as %q so only the node proxy reaches it",
				web, describeHost(b.HostIP), fmt.Sprintf("%s:%d:<container>", WebPublishHost, web))
		}
		published = true
	}
	if published || f.HostNetwork {
		return nil
	}
	return fmt.Errorf("web port %d is not published: add %q to the service that serves it",
		web, fmt.Sprintf("%s:%d:<container>", WebPublishHost, web))
}

// describeHost names a binding's host address for a refusal message.
func describeHost(hostIP string) string {
	if hostIP == "" {
		return "every interface"
	}
	return hostIP
}
