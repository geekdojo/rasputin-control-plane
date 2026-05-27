package bmc

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// RegisterHandlers subscribes the BMC-host agent to:
//
//   - rasputin.node.<nodeID>.cmd.bmc.power.on / off / cycle / reset / status
//   - rasputin.node.<nodeID>.cmd.bmc.sol.open / close
//
// Returns the subscriptions so the caller can Unsubscribe on shutdown.
func RegisterHandlers(nc *nats.Conn, nodeID string, backend Backend) ([]*nats.Subscription, error) {
	h := &handler{nc: nc, backend: backend, sessions: map[string]SOL{}}

	subs := make([]*nats.Subscription, 0, 7)

	for _, verb := range proto.AllBMCPowerVerbs {
		v := verb
		subj := proto.BMCPowerSubject(nodeID, v)
		sub, err := nc.Subscribe(subj, func(m *nats.Msg) { h.power(v, m) })
		if err != nil {
			return subs, err
		}
		subs = append(subs, sub)
		log.Printf("rasputin-agent: subscribed to %s", subj)
	}

	openSubj := proto.BMCSOLOpenSubject(nodeID)
	openSub, err := nc.Subscribe(openSubj, func(m *nats.Msg) { h.solOpen(m) })
	if err != nil {
		return subs, err
	}
	subs = append(subs, openSub)
	log.Printf("rasputin-agent: subscribed to %s", openSubj)

	closeSubj := proto.BMCSOLCloseSubject(nodeID)
	closeSub, err := nc.Subscribe(closeSubj, func(m *nats.Msg) { h.solClose(m) })
	if err != nil {
		return subs, err
	}
	subs = append(subs, closeSub)
	log.Printf("rasputin-agent: subscribed to %s", closeSubj)

	return subs, nil
}

type handler struct {
	nc      *nats.Conn
	backend Backend

	mu       sync.Mutex
	sessions map[string]SOL
	// per-session: the .in subject sub + the pump goroutine cancel.
	pumps map[string]sessionPump
}

type sessionPump struct {
	inSub  *nats.Subscription
	cancel context.CancelFunc
}

func (h *handler) power(verb proto.BMCPowerVerb, m *nats.Msg) {
	var cmd proto.BMCPowerCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.BMCPowerAck{OK: false, Detail: "bad cmd: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state, detail, err := h.backend.Power(ctx, cmd.TargetNodeID, verb)
	if err != nil {
		respond(m, proto.BMCPowerAck{OK: false, State: state, Detail: err.Error()})
		log.Printf("rasputin-agent: bmc.%s on %s: %v", verb, cmd.TargetNodeID, err)
		return
	}
	respond(m, proto.BMCPowerAck{OK: true, State: state, Detail: detail})
}

func (h *handler) solOpen(m *nats.Msg) {
	var cmd proto.BMCSOLOpenCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.BMCSOLOpenAck{OK: false, Detail: "bad cmd: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sol, err := h.backend.OpenSOL(ctx, cmd.TargetNodeID, cmd.SessionID)
	if err != nil {
		respond(m, proto.BMCSOLOpenAck{
			OK:        false,
			SessionID: cmd.SessionID,
			Backend:   h.backend.Name(),
			Detail:    err.Error(),
		})
		return
	}

	// Subscribe to the .in subject (api → device bytes) and forward to
	// the backend session's Write().
	pumpCtx, pumpCancel := context.WithCancel(context.Background())
	inSub, err := h.nc.Subscribe(proto.BMCSOLInSubject(cmd.SessionID), func(msg *nats.Msg) {
		var ev proto.BMCSOLDataEvt
		if err := json.Unmarshal(msg.Data, &ev); err != nil {
			return
		}
		if err := sol.Write([]byte(ev.Data)); err != nil {
			log.Printf("rasputin-agent: sol write: %v", err)
		}
	})
	if err != nil {
		pumpCancel()
		_ = sol.Close()
		respond(m, proto.BMCSOLOpenAck{OK: false, SessionID: cmd.SessionID, Detail: "subscribe .in: " + err.Error()})
		return
	}

	// Forward backend Out → .out subject.
	go func() {
		defer pumpCancel()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case b, ok := <-sol.Out():
				if !ok {
					return
				}
				payload, err := json.Marshal(proto.BMCSOLDataEvt{
					SessionID: cmd.SessionID,
					Data:      string(b),
					Ts:        time.Now().UTC(),
				})
				if err != nil {
					continue
				}
				if err := h.nc.Publish(proto.BMCSOLOutSubject(cmd.SessionID), payload); err != nil {
					log.Printf("rasputin-agent: sol out publish: %v", err)
				}
			}
		}
	}()

	h.mu.Lock()
	if h.pumps == nil {
		h.pumps = map[string]sessionPump{}
	}
	h.sessions[cmd.SessionID] = sol
	h.pumps[cmd.SessionID] = sessionPump{inSub: inSub, cancel: pumpCancel}
	h.mu.Unlock()

	respond(m, proto.BMCSOLOpenAck{
		OK:        true,
		SessionID: cmd.SessionID,
		Backend:   h.backend.Name(),
	})
}

func (h *handler) solClose(m *nats.Msg) {
	var cmd proto.BMCSOLCloseCmd
	if err := json.Unmarshal(m.Data, &cmd); err != nil {
		respond(m, proto.BMCSOLCloseAck{OK: false, Detail: "bad cmd: " + err.Error()})
		return
	}
	h.mu.Lock()
	sol, sok := h.sessions[cmd.SessionID]
	pump, pok := h.pumps[cmd.SessionID]
	delete(h.sessions, cmd.SessionID)
	delete(h.pumps, cmd.SessionID)
	h.mu.Unlock()

	if pok {
		_ = pump.inSub.Unsubscribe()
		pump.cancel()
	}
	if sok {
		_ = sol.Close()
	}
	respond(m, proto.BMCSOLCloseAck{OK: true})
}

func respond(m *nats.Msg, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		log.Printf("rasputin-agent: bmc marshal response: %v", err)
		return
	}
	if err := m.Respond(payload); err != nil {
		log.Printf("rasputin-agent: bmc respond: %v", err)
	}
}
