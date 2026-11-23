package main

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
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

// newIdentityDirty is the drain's signal, built in wireIdentity before the
// session, so the session's writes can use it. Its clock is the host's,
// which the identity service on the same host stamps its events with.
func newIdentityDirty() *events.Signal { return events.NewSignal(time.Now) }

// dirtyAdmin is the session's Admin API caller with one addition: a call that
// is not a GET is recorded open on the drain's signal while it runs, since it
// can store an admin event, and marks the drain dirty once it has succeeded.
// The inner answer and error are returned unchanged.
type dirtyAdmin struct {
	inner idclient.AdminCaller
	dirty interface {
		Begin() (end func())
		MarkDirty()
	}
}

// Admin calls inner and marks dirty after a successful write.
func (a dirtyAdmin) Admin(ctx context.Context, token secret.Value, method, path string, in, out any) (idclient.Response, error) {
	if method == http.MethodGet {
		return a.inner.Admin(ctx, token, method, path, in, out)
	}
	end := a.dirty.Begin()
	resp, err := a.inner.Admin(ctx, token, method, path, in, out)
	end()
	if err == nil {
		a.dirty.MarkDirty()
	}
	return resp, err
}

// identityEvents is the drain, its signal, the throttle and the doors'
// resource version, bound at start.
// The monitor reads its facts from the moment it is built, so each part is
// read through an atomic pointer that is nil until start binds it.
type identityEvents struct {
	signal   atomic.Pointer[events.Signal]
	drainer  atomic.Pointer[events.Drainer]
	throttle atomic.Pointer[policy.Throttle]
	// version is the identity service's resource version the doors serve
	// theme files under (Identity 4.4 hands it to door.Build).
	version atomic.Pointer[door.ResourceVersion]
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

// becameReady is identitystate's BecameReady: the identity service became
// ready, so the drain is marked dirty and the resource version is read again
// (it changes when an upgrade migrates the identity database).
func (e *identityEvents) becameReady() {
	e.markDirty()
	if v := e.version.Load(); v != nil {
		v.Stale()
	}
}

// eventsMarks is the settings store slice the drain keeps its marks in.
type eventsMarks interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// startEvents builds the drain (and, with a door table, the throttle it
// feeds), the marker writer and the converger's recheck as its sinks, and
// the doors' resource version, binds them to the monitor's facts, marks both
// for this start and runs them until ctx ends. It does nothing outside
// keycloak.
func (w identityState) startEvents(ctx context.Context, idw identityWiring, marks eventsMarks, table doors.Table, tableErr error, sinks convergeSinks, log *slog.Logger) {
	ev := w.events
	if ev == nil || idw.mode != identityModeKeycloak || idw.dirty == nil {
		return
	}
	if idw.version != nil {
		rv, err := door.NewResourceVersion(idw.version, log)
		if err != nil {
			log.ErrorContext(ctx, "sign-in door resource version not built", "component", "identity", "err", err.Error())
		} else {
			ev.version.Store(rv)
			rv.Stale()
			go rv.Run(ctx)
		}
	}
	deps, th := eventsDeps(ctx, idw, marks, table, tableErr, sinks, log)
	if th != nil {
		ev.throttle.Store(th)
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

// eventsDeps is the drain's collaborators: the throttle (with a door table)
// as a user and pass sink, the marker writer as a user sink, and the
// converger's sinks (geekdojo/geekdojo-brain#987). It returns the throttle
// it built, nil for none. A part that cannot be built is logged and left
// out.
func eventsDeps(ctx context.Context, idw identityWiring, marks eventsMarks, table doors.Table, tableErr error, sinks convergeSinks, log *slog.Logger) (events.Deps, *policy.Throttle) {
	deps := events.Deps{Admin: idw.session, Marks: marks, Signal: idw.dirty, Realm: identityRealm, Log: log,
		AdminSinks: sinks.admin, PassSinks: append([]events.PassSink{}, sinks.pass...)}
	var th *policy.Throttle
	if tableErr == nil {
		var err error
		th, err = policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: time.Now})
		if err != nil {
			th = nil
			log.ErrorContext(ctx, "sign-in throttle not built", "component", "identity", "err", err.Error())
		} else {
			deps.UserSinks = append(deps.UserSinks, th)
			deps.PassSinks = append(deps.PassSinks, th)
		}
	}
	mw, err := markers.New(markers.Deps{Admin: idw.session, Realm: identityRealm, DoorOf: doorOf(table, tableErr), Log: log})
	if err != nil {
		log.ErrorContext(ctx, "sign-in marker writer not built", "component", "identity", "err", err.Error())
	} else {
		deps.UserSinks = append(deps.UserSinks, mw)
	}
	return deps, th
}

// doorOf is the door each client in the door table belongs to; with no
// table, no client has one. App clients get theirs when Identity 7.3
// registers them.
func doorOf(table doors.Table, tableErr error) func(string) (flows.Door, bool) {
	return func(client string) (flows.Door, bool) {
		switch {
		case tableErr != nil:
			return "", false
		case slices.Contains(table.Home.Clients, client):
			return flows.DoorHome, true
		case slices.Contains(table.App.Clients, client):
			return flows.DoorApp, true
		}
		return "", false
	}
}
