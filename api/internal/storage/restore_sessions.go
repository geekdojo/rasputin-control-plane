package storage

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Custody of a §4.6 private key for the duration of ONE app-volume restore
// (design/storage.md §4.5 phase 2, geekdojo-brain#291).
//
// # Why this exists, and what it is not
//
// Phase 1's restore is a synchronous handler: the key arrives in the request,
// is used, and is zeroed before the handler returns — there is no job for it
// to be a step result of, deliberately, because a job spec is persisted and
// rendered. Phase 2 cannot be synchronous: it stops apps on other nodes and
// streams gigabytes across the LAN, and an operator needs to watch that in
// the Tasks feed like every other long operation. So it is a saga — and a
// saga's spec is in the ledger.
//
// The key therefore never enters the spec. The handler that receives it
// opens a SESSION here — the key copied into memory this package owns — and
// the job carries only the session's id: a random handle that names nothing
// once the session is closed and cannot be turned into the key by anything
// outside this process. The saga's steps and the restore-stream endpoint
// look the session up by that id (or by the job that owns it); the terminal
// hook closes it, which zeroes the key. An api restart loses the session
// with the process, and the saga's step 1 refuses rather than continuing on
// a key it no longer has.
//
// One session is active at a time, and backup.run's step 1 refuses to start
// while one is: a run's prune could delete the very generation a restore is
// reading, and a restore reading the target while a run writes to it is two
// parties on one disk that §4.7 deliberately keeps to one.

// RestoreSession is one lent key and the restore it is lent to.
type RestoreSession struct {
	id  string
	key []byte
	// jobID is the saga the session belongs to, bound once the job exists.
	jobID string
	// The generation the restore reads, where it is mounted, the node the
	// app is on, and the members step 1 planned — set by Arm, consulted by
	// the restore-stream endpoint so a credential can only ever fetch a
	// member the plan names.
	mountPath string
	partUUID  string
	genID     string
	nodeID    string
	members   map[string]restoreMemberFacts
	armed     bool
	openedAt  time.Time
}

// restoreMemberFacts is what the endpoint needs to serve and verify one
// member: the manifest's sealed and plaintext digests and sizes.
type restoreMemberFacts struct {
	sealedSHA256    string
	sealedBytes     uint64
	plaintextSHA256 string
	plaintextBytes  uint64
}

// RestoreSessions holds the open sessions. One per api process.
type RestoreSessions struct {
	mu sync.Mutex
	by map[string]*RestoreSession
	// unboundTTL is how long a session opened by a handler may wait for its
	// job to bind before it is discarded — a handler that died between
	// Open and Bind must not leave a key in memory for the process's life.
	unboundTTL time.Duration
	now        func() time.Time
}

// unboundSessionTTL is the default for the above: a submit is milliseconds.
const unboundSessionTTL = 5 * time.Minute

// ErrRestoreActive is backup.run's refusal while a restore holds a session.
var ErrRestoreActive = errors.New("an app-volume restore is in progress; a backup run would write to — and prune — the target the restore is reading from")

// ErrRestoreSessionGone is the saga's refusal for a session this process no
// longer holds.
var ErrRestoreSessionGone = errors.New("this restore's archive key is no longer held by this api — the api restarted, or the session expired before the job started. Nothing was touched; start the restore again")

// NewRestoreSessions builds an empty registry.
func NewRestoreSessions() *RestoreSessions {
	return &RestoreSessions{by: map[string]*RestoreSession{}, unboundTTL: unboundSessionTTL, now: time.Now}
}

// Open copies key into a new session and returns its id. The caller zeroes
// its own copy; this package zeroes this one on Close.
func (r *RestoreSessions) Open(key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("a restore session holds a 32-byte X25519 private key")
	}
	if allZero(key) {
		return "", errors.New("the supplied key is all zeroes")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	for _, s := range r.by {
		if s.jobID != "" || r.now().Sub(s.openedAt) < r.unboundTTL {
			return "", ErrRestoreActive
		}
	}
	id := "rss-" + randomHex(12)
	held := make([]byte, len(key))
	copy(held, key)
	r.by[id] = &RestoreSession{id: id, key: held, openedAt: r.now().UTC()}
	return id, nil
}

// Bind ties a session to the job that carries its id. Refused for a session
// that is not open or bound to ANOTHER job; binding the same job twice is a
// no-op. Two callers bind: the handler, once Submit has minted the job id,
// and the saga's step 1, which may run first — Submit starts the job's
// goroutine before it returns — and binds the session to the job whose
// spec names it. Whichever comes first wins; a second job naming the same
// session finds it bound elsewhere and refuses.
func (r *RestoreSessions) Bind(id, jobID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.by[id]
	if !ok {
		return ErrRestoreSessionGone
	}
	if strings.TrimSpace(jobID) == "" {
		return errors.New("a session is bound to a job id")
	}
	if s.jobID != "" && s.jobID != jobID {
		return errors.New("the restore session is already bound to another job")
	}
	s.jobID = jobID
	return nil
}

// StreamGrant is what the restore-stream endpoint needs to serve one member:
// where the generation is, the manifest's facts for the member, and a COPY
// of the key — taken under the lock, so a session closing mid-stream cannot
// zero the bytes an unseal is reading. The endpoint zeroes the copy when
// the stream ends.
type StreamGrant struct {
	MountPath       string
	SealedSHA256    string
	SealedBytes     uint64
	PlaintextSHA256 string
	PlaintextBytes  uint64
	key             []byte
}

// Key is the borrowed copy. Zero it with Release when done.
func (g *StreamGrant) Key() []byte { return g.key }

// Release zeroes the copy.
func (g *StreamGrant) Release() {
	if g == nil {
		return
	}
	zeroBytes(g.key)
	g.key = nil
}

// Lookup answers the endpoint's question in one locked read: is there an
// ARMED session for jobID reading generation, and is member in its plan? A
// grant is returned only when all three hold.
func (r *RestoreSessions) Lookup(jobID, generation, member string) (*StreamGrant, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if jobID == "" {
		return nil, false
	}
	for _, s := range r.by {
		if s.jobID != jobID {
			continue
		}
		if !s.armed || s.genID != generation {
			return nil, false
		}
		f, ok := s.members[member]
		if !ok {
			return nil, false
		}
		key := make([]byte, len(s.key))
		copy(key, s.key)
		return &StreamGrant{MountPath: s.mountPath, SealedSHA256: f.sealedSHA256, SealedBytes: f.sealedBytes,
			PlaintextSHA256: f.plaintextSHA256, PlaintextBytes: f.plaintextBytes, key: key}, true
	}
	return nil, false
}

// MemberPlanned reports whether an armed session for jobID reading
// generation plans member, for the node it plans it for — what Mint checks.
func (r *RestoreSessions) MemberPlanned(jobID, generation, member, nodeID string) (planned bool, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.by {
		if s.jobID != jobID || jobID == "" {
			continue
		}
		if !s.armed || s.genID != generation {
			return false, fmt.Sprintf("no restore of generation %s is open for job %s", generation, jobID)
		}
		if _, ok := s.members[member]; !ok {
			return false, fmt.Sprintf("member %s is not in the restore's plan", member)
		}
		if s.nodeID != nodeID {
			return false, fmt.Sprintf("the restore's app is on node %s; a credential for node %s is not minted", s.nodeID, nodeID)
		}
		return true, ""
	}
	return false, fmt.Sprintf("no restore of generation %s is open for job %s", generation, jobID)
}

// Arm records what the saga's step 1 decided: where the generation is, and
// which members the restore may stream. The endpoint serves nothing for a
// session that is not armed.
func (r *RestoreSessions) Arm(id, mountPath, partUUID, genID, nodeID string, members map[string]restoreMemberFacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.by[id]
	if !ok {
		return ErrRestoreSessionGone
	}
	s.mountPath, s.partUUID, s.genID, s.nodeID = mountPath, partUUID, genID, nodeID
	s.members = members
	s.armed = true
	return nil
}

// Get returns the session by id, or nil.
func (r *RestoreSessions) Get(id string) *RestoreSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	return r.by[id]
}

// ByJob returns the session bound to jobID, or nil.
func (r *RestoreSessions) ByJob(jobID string) *RestoreSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.by {
		if s.jobID == jobID && jobID != "" {
			return s
		}
	}
	return nil
}

// Close zeroes the session's key and forgets it. Safe to call twice.
func (r *RestoreSessions) Close(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked(id)
}

// CloseJob closes the session bound to jobID, if any.
func (r *RestoreSessions) CloseJob(jobID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.by {
		if s.jobID == jobID && jobID != "" {
			r.closeLocked(id)
		}
	}
}

// Active reports the job of the session in progress, if any — what
// backup.run's step 1 consults.
func (r *RestoreSessions) Active() (jobID string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	for _, s := range r.by {
		if s.jobID != "" {
			return s.jobID, true
		}
		return "(not yet submitted)", true
	}
	return "", false
}

func (r *RestoreSessions) closeLocked(id string) {
	s, ok := r.by[id]
	if !ok {
		return
	}
	zeroBytes(s.key)
	s.key = nil
	s.members = nil
	s.armed = false
	delete(r.by, id)
}

// sweepLocked discards sessions that were opened and never bound inside
// the TTL.
func (r *RestoreSessions) sweepLocked() {
	for id, s := range r.by {
		if s.jobID == "" && r.now().Sub(s.openedAt) >= r.unboundTTL {
			r.closeLocked(id)
		}
	}
}

// ID is the session's handle.
func (s *RestoreSession) ID() string { return s.id }
