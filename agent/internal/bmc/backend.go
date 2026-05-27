package bmc

import (
	"context"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Backend is the small surface the agent uses to drive each target node's
// BMC. v0 ships MockBackend; RealBackend lands with chassis hardware.
type Backend interface {
	// Name returns "mock" or the production backend's name (e.g. "ipmi",
	// "redfish"). Reported back in BMCPowerAck / BMCSOLOpenAck so the api
	// + UI can label the operation honestly.
	Name() string

	// Power performs a power verb against a target node. Returns the
	// reported post-op state.
	Power(ctx context.Context, target string, verb proto.BMCPowerVerb) (proto.BMCPowerState, string, error)

	// OpenSOL starts a serial-over-LAN session for target. Returns
	// a SOL handle whose Out channel emits bytes from the device; the
	// caller pumps bytes from the bus into Write(). Close() tears it down.
	OpenSOL(ctx context.Context, target, sessionID string) (SOL, error)
}

// SOL is one in-flight serial-over-LAN session on the agent side. The
// handler reads from Out and writes to Write.
type SOL interface {
	SessionID() string
	// Out returns bytes received from the target's serial port.
	Out() <-chan []byte
	// Write sends bytes toward the target's serial port.
	Write(p []byte) error
	// Close tears down the session.
	Close() error
}
