package identitystate

import (
	"context"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// AlertIDPrefix prefixes the state's alert ID; the state follows it.
const AlertIDPrefix = "identity:"

// Alerts reads the state now and returns its alert, or none when the service
// is ready, or in a state that only an injected fact raises and that is not
// raised. Since is when the state was first observed. A reading whose ctx
// ended returns none: nobody is waiting for the list.
func (m *Monitor) Alerts(ctx context.Context, _ time.Time) []proto.Alert {
	r, err := m.read(ctx)
	if err != nil || r.state == Ready {
		return nil
	}
	return []proto.Alert{alertFor(r)}
}

// alertFor is the alert a reading raises. Its title is the state's sentence;
// for Held its detail is the cause the gate's or the start hold's record
// gives.
func alertFor(r reading) proto.Alert {
	a := proto.Alert{
		ID:       AlertIDPrefix + string(r.state),
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSecurity,
		Title:    r.state.sentence(),
		Detail:   r.state.sentence(),
		Since:    r.since,
	}
	if r.state.critical() {
		a.Severity = proto.AlertCrit
	}
	if r.state == Held && r.cause != "" {
		a.Detail = r.cause
	}
	return a
}
