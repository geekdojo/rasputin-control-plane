package main

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The sign-in history drain and the per-source throttle it feeds
// (geekdojo/geekdojo-brain#985, Identity 4.3), under keycloak only: no other
// mode has an identity service, so under off and mock nothing here is built
// and history-behind is never raised.
//
// The drain runs on facts, each of which marks its dirty signal: the api's
// start (startEvents, main's one call), the identity service becoming ready
// (identitystate's BecameReady), an Admin API write that completed
// (dirtyAdmin, wired into the session in wireIdentity), and a forwarded
// request that stores events (the doors, which Identity 4.4 mounts with this
// signal and this throttle).

// newIdentityDirty is the drain's dirty signal, built in wireIdentity before
// the session, so the session's writes can mark it.
func newIdentityDirty() *events.Signal { return events.NewSignal() }

// dirtyAdmin is the session's Admin API caller with one addition: a call that
// is not a GET and succeeded marks the drain dirty, since it can have stored
// an admin event. The inner answer and error are returned unchanged.
type dirtyAdmin struct {
	inner idclient.AdminCaller
	dirty interface{ MarkDirty() }
}

// Admin calls inner and marks dirty after a successful write.
func (a dirtyAdmin) Admin(ctx context.Context, token secret.Value, method, path string, in, out any) (idclient.Response, error) {
	resp, err := a.inner.Admin(ctx, token, method, path, in, out)
	if err == nil && method != http.MethodGet {
		a.dirty.MarkDirty()
	}
	return resp, err
}

// identityEvents is the drain, its signal and the throttle, bound at start.
// The monitor reads its facts from the moment it is built, so each part is
// read through an atomic pointer that is nil until start binds it.
type identityEvents struct {
	signal   atomic.Pointer[events.Signal]
	drainer  atomic.Pointer[events.Drainer]
	throttle atomic.Pointer[policy.Throttle]
	// unbuilt is a drain whose construction failed at start: history-behind.
	unbuilt atomic.Bool
}

// behind is the history-behind fact identitystate reads.
func (e *identityEvents) behind(ctx context.Context) (bool, error) {
	if e.unbuilt.Load() {
		return true, nil
	}
	if d := e.drainer.Load(); d != nil {
		return d.Behind(ctx)
	}
	return false, nil
}

// markDirty marks the drain dirty once it is bound; before start, the start's
// own mark covers whatever happened.
func (e *identityEvents) markDirty() {
	if s := e.signal.Load(); s != nil {
		s.MarkDirty()
	}
}

// eventsMarks is the settings store slice the drain keeps its marks in.
type eventsMarks interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// startEvents builds the drain (and, with a door table, the throttle it
// feeds), binds them to the monitor's facts, marks the drain dirty for this
// start and runs it until ctx ends. It does nothing outside keycloak.
func (w identityState) startEvents(ctx context.Context, idw identityWiring, marks eventsMarks, table doors.Table, tableErr error, log *slog.Logger) {
	ev := w.events
	if ev == nil || idw.mode != identityModeKeycloak || idw.dirty == nil {
		return
	}
	deps := events.Deps{Admin: idw.session, Marks: marks, Signal: idw.dirty, Realm: identityRealm, Log: log}
	if tableErr == nil {
		th, err := policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: time.Now})
		if err != nil {
			log.ErrorContext(ctx, "sign-in throttle not built", "component", "identity", "err", err.Error())
		} else {
			deps.UserSinks = append(deps.UserSinks, th)
			deps.PassSinks = append(deps.PassSinks, th)
			ev.throttle.Store(th)
		}
	}
	d, err := events.New(deps)
	if err != nil {
		ev.unbuilt.Store(true)
		log.ErrorContext(ctx, "sign-in history drain not built", "component", "identity", "err", err.Error())
		return
	}
	ev.drainer.Store(d)
	ev.signal.Store(idw.dirty)
	d.MarkDirty()
	go d.Run(ctx)
}
