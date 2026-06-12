// Package sdnotify implements the systemd notification protocol with the
// stdlib only: READY=1 at startup-complete and WATCHDOG=1 keep-alives.
//
// Why this exists: the OS image's unit files carry WatchdogSec=30 +
// NotifyAccess=main, and systemd enforces that for a non-notifying binary
// by SIGABRTing it 30 seconds after every start. The api shipped with no
// notify support, so every hardware appliance ran in a silent ~33-second
// kill/restart loop from first boot — and every probe we had (QEMU smoke
// healthz polls, bench curls, the entire first-run wizard) fit inside the
// ~28-second live windows, so it passed every gate for five image
// releases. Found on the Mu bench 2026-06-12 via the firewall agent's
// NATS EOF cadence. The watchdog itself is the right call for an
// appliance; the missing half was this package.
//
// An identical copy lives in api/internal/sdnotify (separate Go
// modules; 60 lines doesn't justify a shared module). Keep them in sync.
package sdnotify

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// notify sends one datagram to NOTIFY_SOCKET. No-op (nil error) when the
// env var is unset — dev runs, tests, non-systemd platforms.
func notify(msg string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}

// Ready tells systemd startup is complete (Type=notify services stay
// "activating" until this fires).
func Ready() {
	if err := notify("READY=1"); err != nil {
		log.Printf("sdnotify: READY: %v", err)
	}
}

// StartWatchdog begins WATCHDOG=1 keep-alives when systemd asked for them
// (WATCHDOG_USEC set), petting at half the configured interval. Each pet
// is gated on ping: a liveness probe that should exercise something real
// (e.g. a trivial SQLite query). If ping fails the pet is SKIPPED — a
// genuinely wedged process stops petting and systemd restarts it, which
// is the entire point of having a watchdog. Returns false when systemd
// didn't request a watchdog (dev, or WatchdogSec unset).
func StartWatchdog(ctx context.Context, ping func(context.Context) error) bool {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return false
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		log.Printf("sdnotify: bad WATCHDOG_USEC %q: %v", usecStr, err)
		return false
	}
	interval := time.Duration(usec) * time.Microsecond / 2
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, cancel := context.WithTimeout(ctx, interval/2)
				err := ping(pctx)
				cancel()
				if err != nil {
					log.Printf("sdnotify: liveness ping failed, skipping watchdog pet (systemd will restart us if this persists): %v", err)
					continue
				}
				if err := notify("WATCHDOG=1"); err != nil {
					log.Printf("sdnotify: WATCHDOG: %v", err)
				}
			}
		}
	}()
	log.Printf("sdnotify: watchdog armed, petting every %s", interval)
	return true
}
