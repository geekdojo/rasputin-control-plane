package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// handleJobsWS upgrades to WebSocket and forwards every message on
// rasputin.job.> straight through to the client. Used by the UI's Tasks page
// for live updates.
func (s *Server) handleJobsWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Dev: accept any origin. Production reverse-proxies the UI and api
		// behind one origin so the default same-origin check applies.
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("ws: accept: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	msgs := make(chan []byte, 128)
	sub, err := s.nc.Subscribe(proto.AllJobsFilter, func(m *nats.Msg) {
		select {
		case msgs <- m.Data:
		default:
			// Slow consumer; drop. UI can refetch via REST if needed.
		}
	})
	if err != nil {
		log.Printf("ws: subscribe: %v", err)
		return
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Ping the client periodically so we notice dead connections.
	pings := time.NewTicker(30 * time.Second)
	defer pings.Stop()

	for {
		select {
		case <-ctx.Done():
			c.Close(websocket.StatusNormalClosure, "")
			return
		case <-pings.C:
			pingCtx, pcancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.Ping(pingCtx)
			pcancel()
			if err != nil {
				return
			}
		case msg := <-msgs:
			writeCtx, wcancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.Write(writeCtx, websocket.MessageText, msg)
			wcancel()
			if err != nil {
				return
			}
		}
	}
}
