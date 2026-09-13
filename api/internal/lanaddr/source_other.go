//go:build !linux

package lanaddr

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// SystemSource returns the node's addresses from the standard library's
// interface list. Only Linux delivers address events, and only Linux runs the
// appliance; everywhere else (a developer's Mac) the api takes its start-time
// address and says it will not follow changes. There is no dynamic flag here,
// so every address reads as static.
func SystemSource() Source { return ifaceSource{} }

type ifaceSource struct{}

func (ifaceSource) Subscribe(context.Context) (<-chan struct{}, error) {
	return nil, fmt.Errorf("lanaddr: address change events: %w", errors.ErrUnsupported)
}

func (ifaceSource) List() ([]Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("lanaddr: interfaces: %w", err)
	}
	var out []Addr
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			out = append(out, Addr{
				IP:       ipn.IP.To4(),
				Link:     ifc.Name,
				Index:    ifc.Index,
				Loopback: ifc.Flags&net.FlagLoopback != 0,
			})
		}
	}
	return out, nil
}
