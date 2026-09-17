package bus

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// Client disconnects as events, so a decision that depends on "no such
// connection is open" can be re-made when one closes instead of on a clock
// (geekdojo/geekdojo-brain#448: the switch to TLS-required waits for the last
// plaintext connection to go).
//
// nats-server publishes a client_disconnect advisory on
// $SYS.ACCOUNT.<account>.DISCONNECT in its system account. The api's own
// connection lives in the global account, so the one subject is exported from
// $SYS and imported into $G under disconnectSubject. Nodes cannot read it: the
// credentials the auth callout mints allow subscribing only to their own
// rasputin.node.<id>.cmd.> and _INBOX.>.

// disconnectSubject is the prefix the advisory is imported under.
const disconnectSubject = "rasputin.internal.bus.disconnect"

// OnClientDisconnect calls fn with the server's connection id of every client
// connection in the global account that closes, from the moment it returns.
// Call it once. It keeps working across SetAllowNonTLS: every server this
// Server starts gets the export and import, and the subscription lives on the
// in-process connection, which re-sends it.
//
// Only the RUNNING server's advisories are passed on. Connection ids are
// unique within one server, not across a replacement, so an advisory from the
// server that was just shut down would name an id the new one may reuse.
//
// The advisory is published as the connection is torn down, which can be a
// moment BEFORE the server stops listing it (Connz), so a consumer must treat
// the id it was handed as closed rather than re-read the listing and expect it
// gone. See bustls.Service.NoteDisconnect.
func (s *Server) OnClientDisconnect(fn func(cid uint64)) error {
	ns := s.current()
	if ns == nil {
		return errReplacing
	}
	if err := importDisconnectAdvisory(ns); err != nil {
		return err
	}
	s.mu.Lock()
	s.onDisconnect = fn
	s.mu.Unlock()
	// The import keeps the original subject under the prefix.
	_, err := s.nc.Subscribe(disconnectSubject+".>", func(m *nats.Msg) {
		var ev server.DisconnectEventMsg
		if json.Unmarshal(m.Data, &ev) != nil || ev.Client.ID == 0 {
			return
		}
		if cur := s.current(); cur == nil || ev.Server.ID != cur.ID() {
			return
		}
		fn(ev.Client.ID)
	})
	if err != nil {
		return fmt.Errorf("bus: subscribe disconnect advisories: %w", err)
	}
	return s.nc.Flush()
}

// importDisconnectAdvisory wires one server's disconnect advisory into the
// global account under disconnectSubject.
func importDisconnectAdvisory(ns *server.Server) error {
	sys := ns.SystemAccount()
	if sys == nil {
		return fmt.Errorf("bus: the embedded server has no system account, so it publishes no disconnect advisories")
	}
	subject := fmt.Sprintf("$SYS.ACCOUNT.%s.DISCONNECT", server.DEFAULT_GLOBAL_ACCOUNT)
	if err := sys.AddStreamExport(subject, nil); err != nil {
		return fmt.Errorf("bus: export %s: %w", subject, err)
	}
	if err := ns.GlobalAccount().AddStreamImport(sys, subject, disconnectSubject); err != nil {
		return fmt.Errorf("bus: import %s: %w", subject, err)
	}
	return nil
}
