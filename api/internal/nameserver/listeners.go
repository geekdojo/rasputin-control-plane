package nameserver

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/miekg/dns"
)

// Listeners keeps the nameserver bound on exactly the addresses it is given:
// one [Server] (UDP+TCP) per address, started when the address arrives and
// stopped when it goes (geekdojo/geekdojo-brain#431).
//
// Before this the api bound one address, once, at start. A control plane that
// booted with no DHCP never bound at all, and one whose lease moved kept
// listening on an address it no longer held. The caller now drives Sync from
// kernel address events (package lanaddr), so the bound set follows the node.
type Listeners struct {
	ctx     context.Context
	port    int
	handler dns.Handler
	// listen binds one address. Production uses a real Server; tests substitute
	// a fake so the lifecycle is checkable without privileged sockets.
	listen func(ctx context.Context, ip net.IP) (boundListener, error)

	mu    sync.Mutex
	bound map[string]boundListener // keyed by ip.String()
}

// boundListener is the part of *Server that Listeners uses.
type boundListener interface {
	Stop() error
	UDPAddr() string
}

// NewListeners builds an empty set serving handler on port (53 in production,
// 0 for OS-assigned ports in tests). Every Server it starts stops when ctx ends.
func NewListeners(ctx context.Context, port int, handler dns.Handler) *Listeners {
	l := &Listeners{ctx: ctx, port: port, handler: handler, bound: map[string]boundListener{}}
	l.listen = func(ctx context.Context, ip net.IP) (boundListener, error) {
		srv := NewServer(func() net.IP { return ip }, l.port, l.handler)
		if err := srv.Start(ctx); err != nil {
			return nil, err
		}
		return srv, nil
	}
	return l
}

// SyncResult reports what one Sync changed, for the caller's log line.
type SyncResult struct {
	Started []string // UDP host:port of each listener started
	Stopped []string // address of each listener stopped
	Bound   []string // UDP host:port of every listener bound after the Sync
}

// Changed reports whether the Sync started or stopped anything.
func (r SyncResult) Changed() bool { return len(r.Started) > 0 || len(r.Stopped) > 0 }

// Sync makes the bound set exactly ips.
//
// Listeners on addresses that are no longer wanted are stopped FIRST, and only
// then are new addresses bound. Doing it the other way round would leave, for
// the length of a bind, a listener on an address the node has already dropped —
// and a compute node's cluster-DNS pin probes that very address to decide
// whether its pin is still good (agent/internal/clusterdns). A listener that
// outlives its address is a pin that looks alive when it is not. The cost of
// this order is a gap of one bind (well under a millisecond) with no listener
// on the old address, which is already gone or about to be.
//
// A bind that fails is returned in the joined error and left unbound. It is not
// retried on a timer: the next address event calls Sync again, and a Sync with
// the same set retries only the addresses that are still missing.
func (l *Listeners) Sync(ips []net.IP) (SyncResult, error) {
	want := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			want[ip4.String()] = ip4
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	var res SyncResult
	var errs []error

	for key, srv := range l.bound {
		if _, ok := want[key]; ok {
			continue
		}
		if err := srv.Stop(); err != nil {
			errs = append(errs, err)
		}
		delete(l.bound, key)
		res.Stopped = append(res.Stopped, key)
	}
	if l.ctx.Err() != nil {
		// Shutting down: stopping is fine, binding anew is not.
		res.Bound = l.boundLocked()
		return res, errors.Join(errs...)
	}
	for key, ip := range want {
		if _, ok := l.bound[key]; ok {
			continue
		}
		srv, err := l.listen(l.ctx, ip)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		l.bound[key] = srv
		res.Started = append(res.Started, srv.UDPAddr())
	}
	slices.Sort(res.Started)
	slices.Sort(res.Stopped)
	res.Bound = l.boundLocked()
	return res, errors.Join(errs...)
}

// Bound returns the UDP host:port of every bound listener, sorted.
func (l *Listeners) Bound() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundLocked()
}

func (l *Listeners) boundLocked() []string {
	out := make([]string, 0, len(l.bound))
	for _, srv := range l.bound {
		out = append(out, srv.UDPAddr())
	}
	slices.Sort(out)
	return out
}

// Close stops every listener.
func (l *Listeners) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var errs []error
	for key, srv := range l.bound {
		if err := srv.Stop(); err != nil {
			errs = append(errs, err)
		}
		delete(l.bound, key)
	}
	return errors.Join(errs...)
}
