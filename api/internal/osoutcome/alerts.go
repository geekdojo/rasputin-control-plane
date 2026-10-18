package osoutcome

import (
	"context"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// AlertIDPrefix prefixes each source's alert ID; the kind follows it.
const AlertIDPrefix = "os-outcome:"

// Alerts returns one crit alert per source whose newest job failed. The alert
// clears only when a newer record from the same source records an outcome
// that does not alert. A ledger read that fails is an error, never an empty
// list.
func (r *Reader) Alerts(ctx context.Context, _ time.Time) ([]proto.Alert, error) {
	var out []proto.Alert
	for _, s := range r.srcs {
		newest, err := r.d.Ledger.ListJobsByKind(ctx, s.Kind, 1)
		if err != nil {
			return nil, fmt.Errorf("osoutcome: read %s jobs: %w", s.Kind, err)
		}
		if len(newest) == 0 || newest[0].Status != jobs.StatusFailed {
			continue
		}
		j := newest[0]
		since := j.CreatedAt
		if j.FinishedAt != nil {
			since = *j.FinishedAt
		}
		out = append(out, proto.Alert{
			ID:          AlertIDPrefix + s.Kind,
			Severity:    proto.AlertCrit,
			Source:      proto.AlertSourceJob,
			Title:       s.Title,
			Detail:      j.Error,
			Since:       since,
			RelatedKind: "job",
			RelatedID:   j.ID,
		})
	}
	return out, nil
}
