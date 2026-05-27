package mesh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Compile turns the enabled intents into a canonical state map and its
// SHA-256 hash. Mirrors firewall.Compile: deterministic, stringly-typed
// values, sorted keys.
//
// Shape:
//
//	{
//	  "preauth_keys": [
//	    { "name": "<intent.name>", "user": "...", "reusable": "false",
//	      "ephemeral": "false", "expiresIn": "24h", "tags": "tag:user-device" },
//	    ...
//	  ],
//	  "subnet_routes": [
//	    { "name": "<intent.name>", "nodeId": "node-fw", "cidr": "10.0.0.0/24" },
//	    ...
//	  ]
//	}
func Compile(intents []*Intent) (state map[string]any, hash string, err error) {
	state = map[string]any{}

	var keys []map[string]string
	var routes []map[string]string

	for _, i := range intents {
		if !i.Enabled {
			continue
		}
		switch proto.MeshIntentKind(i.Kind) {
		case proto.IntentPreAuthKey:
			var spec proto.PreAuthKeySpec
			if err := json.Unmarshal(i.Spec, &spec); err != nil {
				return nil, "", fmt.Errorf("intent %s: bad preauth_key spec: %w", i.ID, err)
			}
			tagStr := ""
			if len(spec.Tags) > 0 {
				sort.Strings(spec.Tags)
				tagStr = joinComma(spec.Tags)
			}
			keys = append(keys, map[string]string{
				"name":      i.Name,
				"user":      spec.User,
				"reusable":  fmt.Sprintf("%t", spec.Reusable),
				"ephemeral": fmt.Sprintf("%t", spec.Ephemeral),
				"expiresIn": spec.ExpiresIn,
				"tags":      tagStr,
			})
		case proto.IntentSubnetRoute:
			var spec proto.SubnetRouteSpec
			if err := json.Unmarshal(i.Spec, &spec); err != nil {
				return nil, "", fmt.Errorf("intent %s: bad subnet_route spec: %w", i.ID, err)
			}
			routes = append(routes, map[string]string{
				"name":   i.Name,
				"nodeId": spec.NodeID,
				"cidr":   spec.CIDR,
			})
		}
	}

	sort.Slice(keys, func(a, b int) bool { return keys[a]["name"] < keys[b]["name"] })
	sort.Slice(routes, func(a, b int) bool {
		if routes[a]["nodeId"] != routes[b]["nodeId"] {
			return routes[a]["nodeId"] < routes[b]["nodeId"]
		}
		return routes[a]["cidr"] < routes[b]["cidr"]
	})

	state["preauth_keys"] = keys
	state["subnet_routes"] = routes

	canon, err := json.Marshal(state)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canon)
	return state, hex.EncodeToString(sum[:]), nil
}

// HashObserved produces a hash over a Headscale-derived state shaped the
// same way Compile produces. Used by reconcile.
func HashObserved(state map[string]any) (string, error) {
	canon, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

func joinComma(xs []string) string {
	out := ""
	for i, s := range xs {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
