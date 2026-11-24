package breakglass

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// What the repair page lists. The page renders only these: a power that is
// not listed here does not exist in a repair session.

// RestartKind is the one job a repair session submits in this release.
const RestartKind = "identity.restart"

// The sentences the repair page reads.
const (
	sentenceReady       = "Sign-in is running. Sign in normally, then end this repair session."
	sentenceNoIdentity  = "Sign-in isn't installed on this control plane."
	sentenceStateUnread = "The sign-in service's state couldn't be read."
	reasonNoIdentity    = "Sign-in isn't installed on this control plane, so there is nothing to restart."
)

// Action is one thing the session may do now.
type Action struct {
	// ID names the action to the page: "restart".
	ID string `json:"id"`
	// Kind is the job it submits.
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
	// Reason is why it is disabled; empty when enabled.
	Reason string `json:"reason,omitempty"`
}

// JobView is one job the session submitted.
type JobView struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	// Finished is true once the job has an outcome.
	Finished bool   `json:"finished"`
	Error    string `json:"error,omitempty"`
}

// StateView is GET /api/repair/state's body.
type StateView struct {
	// Sentence is the sign-in service's state in plain words.
	Sentence string `json:"sentence"`
	// Ready is true once sign-in works again.
	Ready bool `json:"ready"`
	// SignInAt is the console's origin, where a person signs in normally.
	SignInAt string    `json:"signInAt"`
	Actions  []Action  `json:"actions"`
	Jobs     []JobView `json:"jobs"`
}

// State is what sess may see and do now: the sign-in service's state, the
// RESTART action, and the jobs sess submitted.
func (s *Service) State(ctx context.Context, sess Session) StateView {
	v := StateView{SignInAt: "https://" + s.d.Facts.ConsoleHost, Jobs: []JobView{}}
	restart := Action{ID: "restart", Kind: RestartKind, Label: "RESTART"}
	switch {
	case s.d.Identity == nil:
		v.Sentence = sentenceNoIdentity
		restart.Reason = reasonNoIdentity
	default:
		st, err := s.d.Identity.State(ctx)
		switch {
		case err != nil:
			s.log.WarnContext(ctx, "The sign-in service's state couldn't be read for the repair page.", "err", err.Error())
			v.Sentence = sentenceStateUnread
		case st == identitystate.Ready:
			v.Sentence, v.Ready = sentenceReady, true
		default:
			v.Sentence = st.Sentence()
		}
		if reason, busy := s.d.Busy(ctx); busy {
			restart.Reason = reason
		} else {
			restart.Enabled = true
		}
	}
	v.Actions = []Action{restart}
	for _, id := range s.sessionJobs(sess) {
		j, err := s.d.Jobs.GetJob(ctx, id)
		if err != nil || j == nil {
			v.Jobs = append(v.Jobs, JobView{ID: id, Status: "unknown", Finished: true, Error: "This job couldn't be read."})
			continue
		}
		v.Jobs = append(v.Jobs, JobView{ID: j.ID, Kind: j.Kind, Status: string(j.Status),
			Finished: j.Status != jobs.StatusQueued && j.Status != jobs.StatusRunning, Error: j.Error})
	}
	return v
}

// Way is one way to make a repair code on this control plane.
type Way struct {
	ID string `json:"id"`
	// Text says where, in a sentence.
	Text string `json:"text"`
	// Command is what to type there.
	Command string `json:"command"`
}

// Ways is GET /api/repair/ways's body: no secret and no session.
type Ways struct {
	SignInAt string `json:"signInAt"`
	Ways     []Way  `json:"ways"`
	// URLs are the addresses a code is typed at.
	URLs []string `json:"urls"`
}

// Ways are the ways that exist on this control plane: its own screen and
// keyboard, its serial console only while it is not the BMC link's host, and
// SSH with -t, which gives the command a terminal to print into.
func (s *Service) Ways() Ways {
	const cmd = "rasputin-api repair-code"
	w := []Way{{ID: "screen", Text: "On the control plane's own screen and keyboard, sign in as root and run:", Command: cmd}}
	if !s.d.Facts.BMCHost() {
		w = append(w, Way{ID: "serial", Text: "On the control plane's serial console, sign in as root and run:", Command: cmd})
	}
	w = append(w, Way{ID: "ssh", Text: "From a computer that holds the control plane's SSH key, run:",
		Command: "ssh -t root@" + s.d.Facts.ConsoleHost + " " + cmd})
	return Ways{SignInAt: "https://" + s.d.Facts.ConsoleHost, Ways: w, URLs: s.RepairURLs()}
}
