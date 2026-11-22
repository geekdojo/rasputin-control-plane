package mesh

import (
	"context"
	"fmt"
	"log"
)

// AppDNS is the minimal app shape the tailnet DNS projection needs: the app
// instance name and the id of the node it is homed on.
type AppDNS struct {
	Name       string
	TargetNode string
}

// SetAppLister installs the source of apps for the tailnet DNS projection. main
// backs it with the apps store. nil (the default) projects no app records.
func (s *Service) SetAppLister(fn func() []AppDNS) { s.appLister = fn }

// ReconcileAppDNS projects each app's tailnet name — <app>.<base-domain> → its
// target node's tailnet IP — into Headscale's hot-reloaded extra_records file
// (ADR-0004 §9). It joins apps to nodes by rasputin node id via the mesh device
// table; an app whose target node isn't enrolled yet (no tailnet IP) is simply
// omitted until it is. Idempotent and safe to call repeatedly — the underlying
// write is stable/sorted, so an unchanged projection doesn't churn the file.
//
// This is the topology-driven reconcile of ADR-0004 §9: tailnet IPs are stable
// across reboots, so it needs to run only when apps or node enrollment change,
// not on the LAN's DHCP churn. It runs on the mesh.reconcile tick and once after
// bring-up.
func (s *Service) ReconcileAppDNS(ctx context.Context) error {
	if s.appLister == nil {
		return nil
	}
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("mesh: list devices for app dns: %w", err)
	}
	bound, dup := BoundDevices(devices)
	for node, ids := range dup {
		// Publishing a name for one of several devices bound to the node
		// would be a guess about which device the node is; its app names
		// are left out until the duplicate is resolved.
		log.Printf("%v; its tailnet app names are not published", &DuplicateBindingError{NodeID: node, HSIDs: ids})
	}
	tailnetIPByNode := make(map[string]string, len(bound))
	for node, d := range bound {
		if d.TailnetIP != "" {
			tailnetIPByNode[node] = d.TailnetIP
		}
	}

	fqdnToIP := make(map[string]string)
	for _, a := range s.appLister() {
		ip := tailnetIPByNode[a.TargetNode]
		if ip == "" || a.Name == "" {
			continue // target node not enrolled yet, or no app name
		}
		// Shares appTailnetFQDN with the leaf SANs so the record and the cert
		// are byte-identical (appleaf.go).
		fqdnToIP[appTailnetFQDN(s.cfg.ClusterID, a.Name)] = ip
	}
	if host, ip := s.appDoorRecord(bound); host != "" {
		fqdnToIP[host] = ip
	}
	return s.sup.ReconcileAppRecords(fqdnToIP)
}

// appDoorRecord is the app sign-in door's MagicDNS record, the door's host
// to the control plane's own tailnet IP (geekdojo/geekdojo-brain#983). It is
// "" unless the door is configured, the withheld predicate is set and says
// no, and the control plane's node has exactly one bound device with a
// tailnet IP. It rides in the same write as the app records, so an unbind,
// a withheld door or a lost IP drops it on the next projection.
func (s *Service) appDoorRecord(bound map[string]*Device) (host, ip string) {
	if s.cfg.AppDoorHost == "" || s.cfg.SelfNodeID == "" {
		return "", ""
	}
	if s.cfg.AppDoorWithheld == nil || s.cfg.AppDoorWithheld() {
		return "", ""
	}
	d := s.selfDevice(bound)
	if d == nil {
		return "", ""
	}
	return s.cfg.AppDoorHost, d.TailnetIP
}

// selfDevice is the control plane's single bound device when it has a tailnet
// IP, else nil. bound is BoundDevices' one-device map, so a node bound to two
// devices has no entry and answers nil. The door's record and the
// app-signin-unjoined warning both read it, so the warning is up exactly when
// the record is absent for want of a joined control plane.
func (s *Service) selfDevice(bound map[string]*Device) *Device {
	d := bound[s.cfg.SelfNodeID]
	if d == nil || d.TailnetIP == "" {
		return nil
	}
	return d
}
