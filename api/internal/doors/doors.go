// Package doors is the sign-in door table (geekdojo/geekdojo-brain#983,
// signin-origin.md §6-§7): one value, built in the composition root from the
// cluster id, that names both sign-in doors. Each door's host, issuer, RP ID
// and leaf come from here, and the names themselves come from proto, so the
// leaf, the DNS records, the agent's routing domain and the issuer handed to
// apps can never disagree (#443's invariant).
package doors

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The doors' names, which name their leaves in the sweep and their
// directories under <data>/tls.
const (
	HomeName = "signin-home"
	AppName  = "signin-app"
)

// Port is the one port both doors are served on (D18's 443 rule).
const Port = 443

// realmPath is the identity service's realm path, appended to a door's
// origin to make its issuer.
const realmPath = "/realms/rasputin"

// ErrNoClusterID is New's answer to an absent or empty cluster id: a dev box
// with no cluster name, where there are no doors. It is not a fault.
var ErrNoClusterID = errors.New("doors: no cluster id")

// ErrNotLabel is a RefusedError's Err for a cluster id that is not a
// lowercase DNS label.
var ErrNotLabel = errors.New("doors: cluster id is not a lowercase DNS label")

// RefusedError is New's answer to a cluster id it will not build doors from.
// It carries the id, so the composition root can log it as a configfault, and
// the rule it broke as Err (ErrNotLabel, proto.ErrClusterIDTooLong or
// proto.ErrClusterIDReservedPrefix), so a consumer can say which rule.
type RefusedError struct {
	ClusterID string
	Reason    string
	Err       error
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("doors: cluster id %q refused: %s", e.ClusterID, e.Reason)
}

// Unwrap returns the rule the id broke.
func (e *RefusedError) Unwrap() error { return e.Err }

// Door is one sign-in door.
type Door struct {
	// Name identifies the door in logs and in the leaf sweep.
	Name string
	// Host is the door's DNS name, which is also its RP ID and the only name
	// on its leaf.
	Host   string
	Port   int
	Issuer string
	RPID   string
	// Clients are the identity service's clients this door serves.
	Clients []string
}

// LeafSpec is the door's leaf: a controlplane-CA server leaf whose only name
// is the door's host, with no IP address, so it shares no name with the api
// leaf (D25) and moves with no LAN address change. ExactDNSNames makes a leaf
// carrying any other name be re-minted.
func (d Door) LeafSpec() tlsca.LeafSpec {
	return tlsca.LeafSpec{
		Usage:         tlsca.UsageServer,
		CommonName:    d.Host,
		DNSNames:      []string{d.Host},
		ExactDNSNames: true,
	}
}

// SetForwarded writes the headers the identity service builds the door's
// addresses from: X-Forwarded-Host, -Proto and -Port. The door's relay and
// the api's own calls that must see the door's issuer (the console's code
// exchange and key fetch, geekdojo/geekdojo-brain#989) both write them here,
// so the two can never disagree.
func (d Door) SetForwarded(h http.Header) {
	h.Set("X-Forwarded-Host", d.Host)
	h.Set("X-Forwarded-Proto", "https")
	h.Set("X-Forwarded-Port", strconv.Itoa(d.Port))
}

// Table names both doors.
type Table struct {
	// Home is the home door, sso-<cid>.local (D25).
	Home Door
	// App is the app door, signin.<cid>.internal.
	App Door
}

// New builds the table for cid. It refuses an empty cid (ErrNoClusterID), a
// cid that is not a lowercase DNS label, and one proto.CheckClusterID refuses:
// over 59 characters, so its sso- label would not be a DNS label, or starting
// with sso-, so its own name would be another cluster's sign-in name. A
// refused id turns both doors off (geekdojo/geekdojo-brain#995).
func New(cid string) (Table, error) {
	if cid == "" {
		return Table{}, ErrNoClusterID
	}
	if !tileschema.ValidDNSLabel(cid) {
		return Table{}, &RefusedError{ClusterID: cid, Reason: "it is not a lowercase DNS label", Err: ErrNotLabel}
	}
	switch err := proto.CheckClusterID(cid); {
	case errors.Is(err, proto.ErrClusterIDTooLong):
		return Table{}, &RefusedError{ClusterID: cid, Err: err,
			Reason: fmt.Sprintf("it is %d characters, and a cluster id allows at most %d so the home door's label fits in 63", len(cid), proto.ClusterIDMaxLen)}
	case err != nil:
		return Table{}, &RefusedError{ClusterID: cid, Err: err,
			Reason: fmt.Sprintf("it starts with %q, which is reserved for sign-in names", proto.SignInHomePrefix)}
	}
	return Table{
		Home: door(HomeName, proto.SignInHomeFQDN(cid), "rasputin-console", "rasputin-reset-home", "rasputin-mesh"),
		App:  door(AppName, proto.SignInFQDN(cid), "rasputin-account", "rasputin-reset-app"),
	}, nil
}

func door(name, host string, clients ...string) Door {
	return Door{
		Name:    name,
		Host:    host,
		Port:    Port,
		Issuer:  "https://" + host + realmPath,
		RPID:    host,
		Clients: clients,
	}
}

// Hosts returns both doors' hosts.
func (t Table) Hosts() []string { return []string{t.Home.Host, t.App.Host} }

// WithheldBy returns the first app name, in sorted order, that is a label the
// doors reserve, or "" when none is. Any reserved name withholds the app door
// (#983 scope).
func WithheldBy(appNames []string) string {
	names := append([]string(nil), appNames...)
	sort.Strings(names)
	for _, n := range names {
		if proto.IsReservedLabel(strings.TrimSpace(n)) {
			return n
		}
	}
	return ""
}
