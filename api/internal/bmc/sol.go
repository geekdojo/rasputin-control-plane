package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
)

// SessionManager owns the lifecycle of in-flight SOL sessions. One
// instance per Service.
//
// Each session:
//
//   1. Open():   generates a session id, RPCs the BMC host's agent on
//                bmc.sol.open, subscribes to the .out subject on success.
//                Returns a *Session the caller (WS handler) reads from.
//   2. Write(s, data): publishes to the .in subject. Agent forwards to
//                the target's serial port.
//   3. Close(s): unsubscribes, RPCs bmc.sol.close, removes from registry.
//
// Backpressure: the .out subscription writes into a buffered channel
// (1024 messages). If the WS consumer can't drain fast enough, new bytes
// are dropped on the floor (logged). A noisy serial console shouldn't be
// allowed to block the bus.
type SessionManager struct {
	svc *Service

	mu       sync.Mutex
	sessions map[string]*Session
}

func NewSessionManager(svc *Service) *SessionManager {
	return &SessionManager{
		svc:      svc,
		sessions: map[string]*Session{},
	}
}

// Session is one in-flight SOL stream. The WS handler reads from Out
// and writes via Write.
type Session struct {
	ID           string
	TargetNodeID string
	Backend      string
	Out          chan []byte
	closeOnce    sync.Once
	closed       chan struct{}

	mgr *SessionManager
	sub *nats.Subscription
}

// Open dispatches a SOL open command to the BMC host's agent, subscribes
// to the .out subject, and returns the live Session. The caller must
// eventually call Close().
func (m *SessionManager) Open(ctx context.Context, targetNodeID string) (*Session, error) {
	if m.svc.cfg.HostNodeID == "" {
		return nil, errors.New("no BMC host node configured")
	}
	sessionID := ulid.Make().String()

	// Subscribe BEFORE the open RPC so we can't miss the initial bytes.
	out := make(chan []byte, 1024)
	closed := make(chan struct{})
	sub, err := m.svc.nc.Subscribe(proto.BMCSOLOutSubject(sessionID), func(msg *nats.Msg) {
		var ev proto.BMCSOLDataEvt
		if err := json.Unmarshal(msg.Data, &ev); err != nil {
			return
		}
		select {
		case out <- []byte(ev.Data):
		default:
			// Backpressure: WS consumer is slow; drop.
			log.Printf("bmc.sol: dropping %d bytes for session %s — consumer slow",
				len(ev.Data), sessionID)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe sol.out: %w", err)
	}

	cmd, _ := json.Marshal(proto.BMCSOLOpenCmd{
		TargetNodeID: targetNodeID,
		SessionID:    sessionID,
	})
	openCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	respMsg, err := m.svc.nc.RequestWithContext(openCtx,
		proto.BMCSOLOpenSubject(m.svc.cfg.HostNodeID), cmd)
	if err != nil {
		_ = sub.Unsubscribe()
		return nil, fmt.Errorf("sol open rpc: %w", err)
	}
	var ack proto.BMCSOLOpenAck
	if err := json.Unmarshal(respMsg.Data, &ack); err != nil {
		_ = sub.Unsubscribe()
		return nil, fmt.Errorf("decode sol open ack: %w", err)
	}
	if !ack.OK {
		_ = sub.Unsubscribe()
		return nil, fmt.Errorf("agent rejected sol open: %s", ack.Detail)
	}

	sess := &Session{
		ID:           sessionID,
		TargetNodeID: targetNodeID,
		Backend:      ack.Backend,
		Out:          out,
		closed:       closed,
		mgr:          m,
		sub:          sub,
	}
	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	publishChange(m.svc, proto.BMCChangeEvt{
		TargetNodeID: targetNodeID,
		Change:       proto.BMCSOLOpened,
		SessionID:    sessionID,
		Detail:       fmt.Sprintf("backend=%s", ack.Backend),
		Ts:           time.Now().UTC(),
	})
	return sess, nil
}

// Write publishes bytes from the WS side onto the .in subject. The agent
// forwards them to the target's serial port.
func (s *Session) Write(data []byte) error {
	payload, err := json.Marshal(proto.BMCSOLDataEvt{
		SessionID: s.ID,
		Data:      string(data),
		Ts:        time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return s.mgr.svc.nc.Publish(proto.BMCSOLInSubject(s.ID), payload)
}

// Close tears down the session: unsubscribe, RPC close to the agent,
// remove from the manager. Safe to call multiple times.
func (s *Session) Close(ctx context.Context) {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.sub != nil {
			_ = s.sub.Unsubscribe()
		}
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd, _ := json.Marshal(proto.BMCSOLCloseCmd{SessionID: s.ID})
		_, _ = s.mgr.svc.nc.RequestWithContext(closeCtx,
			proto.BMCSOLCloseSubject(s.mgr.svc.cfg.HostNodeID), cmd)
		s.mgr.mu.Lock()
		delete(s.mgr.sessions, s.ID)
		s.mgr.mu.Unlock()
		publishChange(s.mgr.svc, proto.BMCChangeEvt{
			TargetNodeID: s.TargetNodeID,
			Change:       proto.BMCSOLClosed,
			SessionID:    s.ID,
			Ts:           time.Now().UTC(),
		})
	})
}

// Closed returns a channel that is closed when the session has been
// torn down.
func (s *Session) Closed() <-chan struct{} { return s.closed }
