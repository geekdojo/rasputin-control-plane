//go:build linux

package bmc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// linuxBusPort is the production busPort: a tty in raw mode at 115,200
// 8N1 with no flow control (the CB04B control-bus line discipline).
// VMIN=0/VTIME=2 makes a read return after 200 ms of silence, which Go
// surfaces as io.EOF — readReply treats that as end-of-reply.
type linuxBusPort struct {
	f *os.File
}

func openBitScopePort(dev string) (busPort, error) {
	// O_NONBLOCK so open can't hang on modem-control lines before
	// CLOCAL is set; cleared again once the termios is in place.
	fd, err := unix.Open(dev, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	tio := unix.Termios{
		Cflag:  unix.CS8 | unix.CLOCAL | unix.CREAD | unix.B115200,
		Ispeed: unix.B115200,
		Ospeed: unix.B115200,
	}
	tio.Cc[unix.VMIN] = 0
	tio.Cc[unix.VTIME] = 2
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &tio); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("termios: %w", err)
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err == nil {
		_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("clear O_NONBLOCK: %w", err)
	}
	return &linuxBusPort{f: os.NewFile(uintptr(fd), dev)}, nil
}

func (p *linuxBusPort) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p *linuxBusPort) Write(b []byte) (int, error) { return p.f.Write(b) }
func (p *linuxBusPort) Close() error                { return p.f.Close() }

func (p *linuxBusPort) DrainInput() error {
	return unix.IoctlSetInt(int(p.f.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
