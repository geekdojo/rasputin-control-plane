package mesh

import (
	"context"
	"fmt"
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
	tailnetIPByNode := make(map[string]string, len(devices))
	for _, d := range devices {
		if d.RasputinNodeID != "" && d.TailnetIP != "" {
			tailnetIPByNode[d.RasputinNodeID] = d.TailnetIP
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
	return s.sup.ReconcileAppRecords(fqdnToIP)
}
