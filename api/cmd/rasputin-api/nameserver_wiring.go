package main

import (
	"net"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nameserver"
)

// controlPlaneSources is every nameserver Source that answers for the control
// plane itself: the console (the zone apex and consoleName, <cid>.local) and,
// while the doors are on, both sign-in doors. main appends the cluster's own
// ClusterSource; the door rig and the #443 invariant test build their lists
// from here, so a name added for the control plane is tested where it is
// served.
//
// Each door's record is the LAN address, read per query. The app door's
// signin.<cid>.internal is withheld while appDoorWithheld says so
// (geekdojo/geekdojo-brain#983). The home door's sso-<cid>.local is an extra
// unicast name beside <cid>.local (Identity 4.15), named by the door table
// (signin-origin §6.1), and is never withheld.
func controlPlaneSources(zone, consoleName string, table doors.Table, doorsOn bool, lan func() net.IP, appDoorWithheld func() bool) []nameserver.Source {
	srcs := []nameserver.Source{nameserver.NewSelfSource(zone, consoleName, lan)}
	if doorsOn {
		srcs = append(srcs,
			nameserver.NewDoorSource(table.Home.Host, lan, homeDoorWithheld),
			nameserver.NewDoorSource(table.App.Host, lan, appDoorWithheld))
	}
	return srcs
}

// homeDoorWithheld is the home door's withheld predicate: nothing withholds
// it. A reserved app name withholds only the app door (doors.WithheldBy).
func homeDoorWithheld() bool { return false }
