// Package secrets is the api's secrets service and its KV repository
// (geekdojo/geekdojo-brain#761, Secrets 3.4).
//
// It has three layers, and no endpoint: each consumer adds its own.
//
//   - Ref is a typed, validated secret reference, apps/<app ID>/<name> or
//     devices/<kind>/<name>. AppSecret, AppKey and DeviceSecret are the parse points
//     an endpoint or job calls (SEC-INPUT), and the only way to name a secret.
//   - KVRepository (the model service) maps a Ref to its path in the
//     rasputin-secrets kv-v2 mount and stores exactly one JSON-string "value"
//     per entry. It makes no business decision.
//   - Service (the business service) authorizes every call before any store
//     call (SEC-AUTHZ), and owns create-only, replace with check-and-set and
//     delete of every version.
//
// No value reaches a log record or an error string: values travel only as
// secret.Value, and every record and error names the reference, never the
// value.
package secrets

import (
	"fmt"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// refKind is which tree a Ref names.
type refKind int

const (
	refNone refKind = iota
	refApp
	refDevice
	// refAppRuntime is an entry an app wrote itself at runtime, through its
	// relay socket (geekdojo/geekdojo-brain#1081): apps/<ID>/_runtime/<name>.
	refAppRuntime
	// refAppKey is one of an app's own Transit keys
	// (geekdojo/geekdojo-brain#1084): app-<ID>-<name> in the app-keys mount.
	refAppKey
)

// appRuntimeSegment is the path segment the entries an app writes at runtime
// sit under. It is not a DNS-1123 label, so no pushed secret's name can ever
// equal it, and the two trees never meet.
const appRuntimeSegment = "_runtime"

// Ref is a parsed secret reference. Its fields are unexported, so only
// AppSecret, AppRuntimeSecret and DeviceSecret make one; the zero Ref names nothing and is
// refused everywhere.
type Ref struct {
	kind refKind
	// owner is the app ID for an app secret, the device kind for a device one.
	owner string
	name  string
}

// AppSecret is the reference to app appID's secret name. appID must be a
// canonical upper-case ULID, as the api mints them, so one app cannot have two
// paths; a lower-case spelling is refused rather than folded. name must be a
// ${secret:} name (tileschema.ValidSecretName, a DNS-1123 label).
func AppSecret(appID, name string) (Ref, error) {
	if !proto.ValidAppID(appID) || strings.ToUpper(appID) != appID {
		return Ref{}, fmt.Errorf("%w: the app ID is not a canonical upper-case ULID", ErrInvalidRef)
	}
	if !tileschema.ValidSecretName(name) {
		return Ref{}, fmt.Errorf("%w: the secret name is not a DNS-1123 label", ErrInvalidRef)
	}
	return Ref{kind: refApp, owner: appID, name: name}, nil
}

// AppRuntimeSecret is the reference to the entry name that app appID wrote
// itself at runtime, through its relay socket (geekdojo/geekdojo-brain#1081):
// apps/<ID>/_runtime/<name>. appID and name follow AppSecret's rules.
func AppRuntimeSecret(appID, name string) (Ref, error) {
	r, err := AppSecret(appID, name)
	if err != nil {
		return Ref{}, err
	}
	r.kind = refAppRuntime
	return r, nil
}

// AppKey is the reference to app appID's Transit key name
// (geekdojo/geekdojo-brain#1084). appID and name follow AppSecret's rules. The
// key's name in the store is app-<ID>-<name>: an ID is 26 Crockford
// characters with no '-', so each key name parses back to exactly one (app,
// name) pair.
func AppKey(appID, name string) (Ref, error) {
	r, err := AppSecret(appID, name)
	if err != nil {
		return Ref{}, err
	}
	r.kind = refAppKey
	return r, nil
}

// DeviceSecret is the reference to device secret name of kind. Both must be
// DNS-1123 labels. The service refuses every operation on it for now: no
// consumer exists yet, and the first one adds its actor and its rule.
func DeviceSecret(kind, name string) (Ref, error) {
	if !tileschema.ValidDNSLabel(kind) {
		return Ref{}, fmt.Errorf("%w: the device kind is not a DNS-1123 label", ErrInvalidRef)
	}
	if !tileschema.ValidDNSLabel(name) {
		return Ref{}, fmt.Errorf("%w: the secret name is not a DNS-1123 label", ErrInvalidRef)
	}
	return Ref{kind: refDevice, owner: kind, name: name}, nil
}

// String is the reference's path under the mount, apps/<ID>/<name> or
// devices/<kind>/<name>, transit:app-<ID>-<name> for an app key, and empty
// for the zero Ref. It is for logs: names
// are not secret.
func (r Ref) String() string {
	switch r.kind {
	case refApp:
		return "apps/" + r.owner + "/" + r.name
	case refAppRuntime:
		return "apps/" + r.owner + "/" + appRuntimeSegment + "/" + r.name
	case refDevice:
		return "devices/" + r.owner + "/" + r.name
	case refAppKey:
		return "transit:" + r.keyName()
	}
	return ""
}

// keyName is an app key's name in the Transit mount, app-<ID>-<name>.
func (r Ref) keyName() string { return "app-" + r.owner + "-" + r.name }

func (r Ref) valid() bool { return r.kind != refNone }
