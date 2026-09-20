package busauth

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// One live session per token, newest wins (geekdojo/geekdojo-brain#500).
//
// # The rule
//
// A join token is one node's machine identity, and a node runs one agent,
// which holds one bus connection. The Step 0 probe measured that across seven
// nodes over four minutes: every agent held exactly one NATS connection, so
// nothing legitimate keeps two. Admit therefore disconnects whatever session
// the presented token already held before it records the new one.
//
// # Why newest wins, and not "refuse while one is live"
//
// Refusing the newer connection would hand a thief a denial of service: hold
// the token open and the real node can never come back. It would also strand
// a node whose previous session the api has not yet noticed is gone. Newest
// wins keeps the node's own reconnect working in every case, and makes the
// theft noisy rather than silent — the two presenters evict each other, and
// the alternation is what raises the alert below.
//
// # What is recorded
//
// Every eviction is logged with both presenters, the node and the token id
// (the hash — never the token itself). An ordinary reconnect is not an
// eviction: Admit prunes closed sessions first, so a takeover means the old
// connection was still open when the new one authenticated.
//
// # The alert
//
// One eviction is ordinary — a node whose old connection had not been reaped
// yet, or an agent restarted under a stuck TCP session. Two presenters
// ALTERNATING is not: it means two machines both hold the token and are taking
// the session from each other. That is what alternations counts, and what
// raises bus-session-alternating.
//
// The counter is not a rate and has no window: the fact is "this token's
// session has changed hands back and forth", which does not stop being true
// because time passed (principles.md — no clock-driven state). It is cleared
// by facts, not by a timer: the node's token is revoked or the node is removed
// (both make the registry exclude the node, which calls ForgetNode), or the
// api restarts. Timestamps here are for the operator to read; nothing decides
// on them.
//
// # Memory
//
// A record exists only for a token that has actually been taken over, so a
// healthy cluster holds none, and there can never be more than one per token.
// Nothing here caches node state: membership and token liveness live in the
// api's one node registry (inventory.Registry), which is also what tells this
// store when to forget a node.

// takeoverHostsKept bounds the hosts named in one record's alert text. Two is
// the interesting case; more are counted but not all listed, so a token being
// presented from a dozen places cannot grow the record without bound.
const takeoverHostsKept = 4

// takeover is one token's history of losing its session to another connection.
type takeover struct {
	nodeID string
	// evictions is how many times a new connection took this token's session.
	evictions int
	// alternations is how many of those handed the session back to the
	// presenter the previous takeover had evicted — two presenters trading it.
	alternations int
	// lastEvicted is the host the most recent takeover evicted, and the one an
	// alternation is detected against.
	lastEvicted string
	// hosts are the presenters seen, in first-seen order, capped.
	hosts []string
	// alternatingSince and lastAt are for display only.
	alternatingSince time.Time
	lastAt           time.Time
}

// takeovers is the Store's record of contested tokens. Its own lock: Admit
// takes it inside the session lock (sessions.mu → takeovers.mu), and
// ForgetNode — called from the node registry's exclusion hook — takes only
// this one, so the hook can never wait on the session lock.
type takeovers struct {
	mu      sync.Mutex
	byToken map[string]*takeover
	// now is the clock the records are stamped with; nil is time.Now. Tests
	// pin it so the alert's text is deterministic.
	now func() time.Time
}

func (t *takeovers) clock() time.Time {
	if t.now != nil {
		return t.now().UTC()
	}
	return time.Now().UTC()
}

// evictSuperseded closes every session the token already held and records the
// takeover. Called by Admit with the session lock released.
func (s *Store) evictSuperseded(d Disconnector, conn Conn, tokenID, nodeID string, superseded []heldSession) {
	for _, h := range superseded {
		closed := d.DisconnectClient(h.serverID, h.cid)
		// The node id is validated before Admit is reached and the hosts come
		// from the server, but both are stripped of line breaks so no value
		// can forge a second log line.
		log.Printf("busauth: bus session taken over: node=%q token=%s newest connection cid=%d from %q; previous session cid=%d from %q disconnected=%v — a join token holds one live session",
			oneLine(nodeID), tokenID, conn.CID, oneLine(conn.Host), h.cid, oneLine(h.host), closed)
		s.noteTakeover(tokenID, nodeID, h.host, conn.Host)
	}
}

// noteTakeover records one eviction, and whether it was an alternation: the
// incoming presenter is the one the PREVIOUS takeover of this token evicted,
// and is not the one just evicted. A node reconnecting from its own address
// over and over is never an alternation, however often it happens.
func (s *Store) noteTakeover(tokenID, nodeID, evictedHost, newHost string) {
	s.tk.mu.Lock()
	defer s.tk.mu.Unlock()
	if s.tk.byToken == nil {
		s.tk.byToken = map[string]*takeover{}
	}
	now := s.tk.clock()
	r := s.tk.byToken[tokenID]
	if r == nil {
		r = &takeover{nodeID: nodeID}
		s.tk.byToken[tokenID] = r
	}
	r.evictions++
	r.lastAt = now
	r.noteHost(evictedHost)
	r.noteHost(newHost)
	if evictedHost != "" && newHost != "" && evictedHost != newHost {
		if r.lastEvicted == newHost {
			r.alternations++
			if r.alternatingSince.IsZero() {
				r.alternatingSince = now
			}
		}
		r.lastEvicted = evictedHost
	}
}

func (r *takeover) noteHost(host string) {
	if host == "" || len(r.hosts) >= takeoverHostsKept {
		return
	}
	for _, h := range r.hosts {
		if h == host {
			return
		}
	}
	r.hosts = append(r.hosts, host)
}

// ForgetNode drops every takeover record for nodeID. It is wired to the node
// registry's exclusion hook (inventory.Registry.OnNodeExcluded), so the alert
// clears on the fact that ends it — the node's token was revoked, or the node
// was removed — rather than on a timer. Safe to call for a node with no
// record.
func (s *Store) ForgetNode(nodeID string) {
	if nodeID == "" {
		return
	}
	s.tk.mu.Lock()
	defer s.tk.mu.Unlock()
	for id, r := range s.tk.byToken {
		if r.nodeID == nodeID {
			delete(s.tk.byToken, id)
		}
	}
}

// SessionAlerts is the alerts aggregator's supplier (wired by main through
// alerts.Service.SetBusSessionAlerts): one crit per node whose join token two
// presenters are trading the bus session between. A node whose token was
// merely evicted once raises nothing — that is in the log, not on the alerts
// page.
//
// Computed on read from the records above, with a stable id per node, so a
// second read is the same alert and not a second one; it is gone once the
// records are (ForgetNode, or an api restart).
func (s *Store) SessionAlerts(now time.Time) []proto.Alert {
	type merged struct {
		alternations int
		since        time.Time
		last         time.Time
		hosts        []string
	}
	s.tk.mu.Lock()
	byNode := map[string]*merged{}
	for _, r := range s.tk.byToken {
		if r.alternations == 0 {
			continue
		}
		m := byNode[r.nodeID]
		if m == nil {
			m = &merged{since: r.alternatingSince, last: r.lastAt}
			byNode[r.nodeID] = m
		}
		m.alternations += r.alternations
		if !r.alternatingSince.IsZero() && r.alternatingSince.Before(m.since) {
			m.since = r.alternatingSince
		}
		if r.lastAt.After(m.last) {
			m.last = r.lastAt
		}
		for _, h := range r.hosts {
			m.hosts = appendUnique(m.hosts, h)
		}
	}
	s.tk.mu.Unlock()

	out := make([]proto.Alert, 0, len(byNode))
	for node, m := range byNode {
		since := m.since
		if since.IsZero() {
			since = now
		}
		out = append(out, proto.Alert{
			ID:       "bus-session-alternating:" + node,
			Severity: proto.AlertCrit,
			Source:   proto.AlertSourceSecurity,
			Title:    fmt.Sprintf("Node %s's join token is in use from more than one place", node),
			Detail: fmt.Sprintf("The bus session for %s has been taken back and forth between presenters %d time(s) — seen from %s, most recently %s. A join token holds one live session, so each connection disconnects the other. Revoke this node's token and re-provision the node; the alert clears when the token is revoked or the node is removed.",
				node, m.alternations, strings.Join(m.hosts, ", "), m.last.Format(time.RFC3339)),
			Since:       since,
			RelatedKind: "node",
			RelatedID:   node,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
