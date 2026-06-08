package ids

import (
	"context"
	"encoding/json"
	"log"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Service subscribes to rasputin.node.*.evt.ids.> and appends each
// alert to a Writer-managed JSONL file. The controlplane's Alloy then
// tails that file via loki.source.file and ships to Loki — the UI
// queries via the existing /api/obs/logs LogQL proxy.
//
// No SQLite ring buffer like metrics has — Loki is the persistent
// store for IDS alerts. If Loki is off (RASPUTIN_OBS_LOKI != 1) the
// alerts still land in the JSONL file on disk; operators can `tail -f`
// or use a one-off `jq` query, and the file is small (rotates at
// DefaultMaxBytes).
type Service struct {
	writer *Writer
	nc     *nats.Conn

	cancel context.CancelFunc
	sub    *nats.Subscription
}

// NewService constructs the service against an existing Writer (the
// caller manages writer.Close() lifecycle since it might want to
// flush on shutdown independent of Stop).
func NewService(writer *Writer, nc *nats.Conn) *Service {
	return &Service{writer: writer, nc: nc}
}

func (s *Service) Start(ctx context.Context) error {
	_, s.cancel = context.WithCancel(ctx)
	sub, err := s.nc.Subscribe(proto.AllIDSAlertsFilter, s.handle)
	if err != nil {
		return err
	}
	s.sub = sub
	return nil
}

func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.sub != nil {
		_ = s.sub.Unsubscribe()
	}
}

func (s *Service) handle(m *nats.Msg) {
	var ev proto.IDSAlertEvt
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		log.Printf("ids: decode %s: %v", m.Subject, err)
		return
	}
	if ev.NodeID == "" {
		log.Printf("ids: drop event on %s: empty nodeId", m.Subject)
		return
	}
	if err := s.writer.Write(&ev); err != nil {
		log.Printf("ids: write %s: %v", ev.NodeID, err)
	}
}
