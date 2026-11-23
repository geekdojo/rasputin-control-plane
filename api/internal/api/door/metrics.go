package door

import "time"

// The doors' metric names. Identity 4.4 publishes them when it mounts the
// doors; until then nothing scrapes them.
const (
	MetricRequests         = "rasputin_signin_door_requests_total"
	MetricThrottledSources = "rasputin_signin_throttled_sources"
)

// Waiting counts the sources waiting at a door: *policy.Throttle.
type Waiting interface {
	Waiting(door Kind, now time.Time) int
}

// Counts are one door's metric values.
type Counts struct {
	Door             Kind
	Requests         uint64
	ThrottledSources int
}

// Counts reads the door's request count and, from w, how many sources wait
// at it now.
func (h *Handler) Counts(w Waiting, now time.Time) Counts {
	return Counts{Door: h.cfg.Kind, Requests: h.requests.Load(), ThrottledSources: w.Waiting(h.cfg.Kind, now)}
}
