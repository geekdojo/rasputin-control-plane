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
	"sort"
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

// RefusedError is New's answer to a cluster id it will not build doors from.
// It carries the id, so the composition root can log it as a configfault.
type RefusedError struct {
	ClusterID string
	Reason    string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("doors: cluster id %q refused: %s", e.ClusterID, e.Reason)
}

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

// Table names both doors.
type Table struct {
	// Home is the home door, sso-<cid>.local (D25).
	Home Door
	// App is the app door, signin.<cid>.internal.
	App Door
}

// New builds the table for cid. It refuses an empty cid (ErrNoClusterID), a
// cid that is not a lowercase DNS label, and one whose sso- label would not be
// a DNS label (over 59 characters).
func New(cid string) (Table, error) {
	if cid == "" {
		return Table{}, ErrNoClusterID
	}
	if !tileschema.ValidDNSLabel(cid) {
		return Table{}, &RefusedError{ClusterID: cid, Reason: "it is not a lowercase DNS label"}
	}
	if home := proto.SignInHomePrefix + cid; !tileschema.ValidDNSLabel(home) {
		return Table{}, &RefusedError{ClusterID: cid, Reason: fmt.Sprintf("the home door's label %q would exceed 63 characters", home)}
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
