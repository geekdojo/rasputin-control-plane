package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/lanaddr"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/signinname"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// staticAddrs hands a subscriber one snapshot.
type staticAddrs struct{ s lanaddr.Snapshot }

func (a staticAddrs) Subscribe(fn func(prev, next lanaddr.Snapshot)) { fn(lanaddr.Snapshot{}, a.s) }

// recConn records the questions of each datagram sent.
type recConn struct {
	mu     sync.Mutex
	sent   []*dns.Msg
	first  chan struct{}
	once   sync.Once
	closed chan struct{}
	cOnce  sync.Once
}

func (c *recConn) Read([]byte) (int, netip.AddrPort, error) {
	<-c.closed
	return 0, netip.AddrPort{}, net.ErrClosed
}

func (c *recConn) Send(b []byte) error {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return err
	}
	c.mu.Lock()
	c.sent = append(c.sent, m)
	c.mu.Unlock()
	c.once.Do(func() { close(c.first) })
	return nil
}

func (c *recConn) Close() error { c.cOnce.Do(func() { close(c.closed) }); return nil }

// TC-995-17: wireSigninName's three branches.
func TestWireSigninName(t *testing.T) {
	lan := lanaddr.Select([]lanaddr.Addr{{IP: net.ParseIP("192.168.1.20"), Link: "end0", Index: 2, Dynamic: true}})
	noOpen := func(int) (signinname.Conn, error) { t.Fatal("Open called"); return nil, nil }

	t.Run("no cluster id", func(t *testing.T) {
		log, rec := logkittest.New()
		tbl, err := doors.New("")
		r := wireSigninName(t.Context(), log, tbl, err, staticAddrs{lan}, noOpen, signinname.SystemClock{})
		if r != nil {
			t.Fatalf("got a responder %v", r)
		}
		if recs := rec.Records(); len(recs) != 1 || recs[0].Level != slog.LevelInfo || recs[0].Message != "sign-in name responder off: no cluster id" {
			t.Errorf("records:\n%s", rec.Text())
		}
		r.Wait() // shutdown completes with no responder
		inner := &countingSink{}
		if got := signinNameFanout(inner, &obs.VMSink{}, r, "cp1", log); got != metrics.Sink(inner) {
			t.Errorf("fanout with no responder = %T, want the inner sink unchanged", got)
		}
	})

	t.Run("refused", func(t *testing.T) {
		log, rec := logkittest.New()
		tbl, err := doors.New("sso-bench")
		r := wireSigninName(t.Context(), log, tbl, err, staticAddrs{lan}, noOpen, signinname.SystemClock{})
		if r == nil {
			t.Fatal("no refused responder")
		}
		if n := len(rec.AtLevel(slog.LevelError)); n != 0 {
			t.Errorf("%d ERROR records; wireDoorTable logs the configfault", n)
		}
		r.Wait()
		a := r.Alerts(time.Now())
		if len(a) != 1 || a[0].ID != signinname.AlertRefused || a[0].Source != proto.AlertSourceSecurity {
			t.Errorf("alerts %+v", a)
		}
	})

	t.Run("valid", func(t *testing.T) {
		log, _ := logkittest.New()
		tbl, err := doors.New("bench")
		conn := &recConn{first: make(chan struct{}), closed: make(chan struct{})}
		var opened []int
		open := func(idx int) (signinname.Conn, error) { opened = append(opened, idx); return conn, nil }
		ctx, cancel := context.WithCancel(t.Context())
		r := wireSigninName(ctx, log, tbl, err, staticAddrs{lan}, open, signinname.SystemClock{})
		if r == nil {
			t.Fatal("no responder")
		}
		select {
		case <-conn.first:
		case <-time.After(10 * time.Second):
			t.Fatal("hung: the responder was not started")
		}
		cancel()
		r.Wait()
		conn.mu.Lock()
		defer conn.mu.Unlock()
		if q := conn.sent[0].Question; len(q) != 1 || q[0].Name != tbl.Home.Host+"." {
			t.Errorf("first probe asks %v, want %s", q, tbl.Home.Host)
		}
		if len(opened) != 1 || opened[0] != 2 {
			t.Errorf("opened %v", opened)
		}
		inner := &countingSink{}
		if got := signinNameFanout(inner, &obs.VMSink{}, r, "cp1", log); got == metrics.Sink(inner) {
			t.Error("fanout with a responder returned the inner sink undecorated")
		}
		if got := signinNameFanout(inner, &obs.VMSink{}, r, "", log); got != metrics.Sink(inner) {
			t.Error("fanout with no self node id decorated the sink")
		}
	})
}

type countingSink struct{ n int }

func (c *countingSink) Write(context.Context, *proto.MetricsEvt) error { c.n++; return nil }
