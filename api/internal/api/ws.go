package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
)

// bridgeSubject returns an http.HandlerFunc that upgrades to WebSocket and
// forwards every message published on subjectFilter straight to the client.
// Used to back the UI's live-update endpoints.
func (s *Server) bridgeSubject(subjectFilter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Dev: accept any origin. Production reverse-proxies the UI and
			// api behind one origin so the default same-origin check applies.
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
		sub, err := s.nc.Subscribe(subjectFilter, func(m *nats.Msg) {
			select {
			case msgs <- m.Data:
			default:
				// Slow consumer; drop. UI can refetch via REST if needed.
			}
		})
		if err != nil {
			log.Printf("ws: subscribe %s: %v", subjectFilter, err)
			return
		}
		defer func() { _ = sub.Unsubscribe() }()

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
}
