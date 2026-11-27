package breakglass

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// What the repair page lists. The page renders only these: a power that is
// not listed here does not exist in a repair session.

// RestartKind is the sign-in service's restart, a job a repair session
// submits.
const RestartKind = "identity.restart"

// MoveKind is identity.move (move.Kind), which a repair session re-runs
// (C9). This package can't import identity/move, whose tests import it.
const MoveKind = "identity.move"

// The sentences the repair page reads.
const (
	sentenceReady       = "Sign-in is running. Sign in normally, then end this repair session."
	sentenceNoIdentity  = "Sign-in isn't installed on this control plane."
	sentenceStateUnread = "The sign-in service's state couldn't be read."
	reasonNoIdentity    = "Sign-in isn't installed on this control plane, so there is nothing to restart."

	labelReset        = "RESET THIS ADMIN'S SIGN-IN"
	reasonResetUsed   = "This repair session has already reset a sign-in. Make a new repair code to reset another."
	reasonResetUnread = "The accounts couldn't be read, so no sign-in can be reset now. If sign-in isn't running, restart it first."
	reasonNoTargets   = "No administrator or designated account exists on this cluster, so there is no sign-in to reset."
	labelMove         = "BRING BACK THE ACCOUNTS FROM BEFORE THE UPDATE…"
)

// Target is an account the reset may act on: its id and its sign-in name.
type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Action is one thing the session may do now.
type Action struct {
	// ID names the action to the page: "restart", "reset" or "move".
	ID string `json:"id"`
	// Kind is the job it submits.
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
	// Reason is why it is disabled; empty when enabled.
	Reason string `json:"reason,omitempty"`
	// Targets are the accounts the reset may act on.
	Targets []Target `json:"targets,omitempty"`
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
	if a, ok := s.resetAction(ctx, sess); ok {
		v.Actions = append(v.Actions, a)
	}
	if a, ok := s.moveAction(ctx); ok {
		v.Actions = append(v.Actions, a)
	}
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
// keyboard, its serial console only while it is not the BMC link's host and
// a serial login runs on it, and SSH with -t, which gives the command a
// terminal to print into.
func (s *Service) Ways(ctx context.Context) Ways {
	const cmd = "rasputin-api repair-code"
	w := []Way{{ID: "screen", Text: "On the control plane's own screen and keyboard, sign in as root and run:", Command: cmd}}
	if s.serialLogin(ctx) {
		w = append(w, Way{ID: "serial", Text: "On the control plane's serial console, sign in as root and run:", Command: cmd})
	}
	w = append(w, Way{ID: "ssh", Text: "From a computer that holds the control plane's SSH key, run:",
		Command: "ssh -t root@" + s.d.Facts.ConsoleHost + " " + cmd})
	return Ways{SignInAt: "https://" + s.d.Facts.ConsoleHost, Ways: w, URLs: s.RepairURLs()}
}

// serialLogin is whether the serial console offers a root login now: never
// on the BMC link's host, which is checked first and reads no unit, and
// otherwise only while a serial login getty runs. A login state that can't
// be read offers none (ERR-CLOSED), with a WARN.
func (s *Service) serialLogin(ctx context.Context) bool {
	if s.d.Facts.BMCHost() {
		return false
	}
	on, err := s.d.Facts.SerialLogin(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "The serial console's login state couldn't be read for the repair page.", "event", "breakglass.serial_unread", "err", err.Error())
		return false
	}
	return on
}

// resetAction is the reset (C1), listed whenever it is wired: disabled once
// the session has reset one, when the accounts can't be read, or when there
// is none to reset.
func (s *Service) resetAction(ctx context.Context, sess Session) (Action, bool) {
	if s.d.Resets == nil {
		return Action{}, false
	}
	a := Action{ID: "reset", Kind: accounts.RepairResetKind, Label: labelReset}
	if s.resetUsed(sess) {
		a.Reason = reasonResetUsed
		return a, true
	}
	ts, err := s.d.Resets.Targets(ctx)
	switch {
	case err != nil:
		s.log.WarnContext(ctx, "The reset's accounts couldn't be read for the repair page.", "event", "breakglass.targets_unread", "err", err.Error())
		a.Reason = reasonResetUnread
	case len(ts) == 0:
		a.Reason = reasonNoTargets
	default:
		a.Enabled = true
		for _, t := range ts {
			a.Targets = append(a.Targets, Target{ID: t.ID, Name: t.Username})
		}
	}
	return a, true
}

// moveAction is the move's re-run (C9), listed only while C9's state
// holds. A state that can't be read lists nothing (ERR-CLOSED), with a WARN.
func (s *Service) moveAction(ctx context.Context) (Action, bool) {
	if s.d.Move == nil {
		return Action{}, false
	}
	r, err := s.d.Move.Repair(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "The accounts from before the update couldn't be read for the repair page.", "event", "breakglass.move_unread", "err", err.Error())
		return Action{}, false
	}
	if !r.Holds {
		return Action{}, false
	}
	return Action{ID: "move", Kind: MoveKind, Label: labelMove, Enabled: true}, true
}
