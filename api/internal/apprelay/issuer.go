// Package apprelay is the api's half of the app relay
// (geekdojo/geekdojo-brain#1081): a first-party app granted a runtime
// identity reaches its own secrets through a TLS Unix socket its node's agent
// opens for it, never the store itself (the 2026-11-15 ruling on
// geekdojo/geekdojo-brain#1079, ADR-0011).
//
// Three layers (ARCH-BL):
//
//   - Issuer gives an app its socket at every push and takes it away at
//     delete, over the app.relay verb. It implements apps.AppIdentityIssuer.
//   - Service is the business layer for an app's calls: it refuses an app
//     that is not granted, keeps the deletion index, and calls the secrets
//     service as the app (secrets.RuntimeActor), which authorizes the call.
//   - Handler is the bus endpoint: it takes the node from the subject the
//     broker authenticated, parses the call strictly, and maps the service's
//     answer to a stable code, a safe sentence and a correlation id.
package apprelay

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Requester is the bus request the issuer makes of an agent. *nats.Conn
// satisfies it.
type Requester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
}

// Signer signs a leaf over a public key generated elsewhere. *tlsca.CA
// satisfies it.
type Signer interface {
	SignLeaf(spec tlsca.LeafSpec, pub crypto.PublicKey) ([]byte, error)
}

// SilenceExplainer reads why a node-scoped request drew no responder.
// *inventory.Store satisfies it.
type SilenceExplainer interface {
	ExplainNoResponder(ctx context.Context, subject string) inventory.NoResponder
}

// IssuerDeps is what an Issuer needs. Signer, CACert and CAPEM are the
// controlplane CA; when it did not load they are nil, and every Issue is
// refused (ERR-CLOSED) while the api and every app that is not granted carry
// on.
type IssuerDeps struct {
	Bus     Requester
	Signer  Signer
	CACert  *x509.Certificate
	CAPEM   []byte
	Silence SilenceExplainer
}

// Issuer implements apps.AppIdentityIssuer over the app.relay verb.
type Issuer struct {
	d IssuerDeps
}

// relayCommonName is the CommonName on every relay server leaf. Cosmetic:
// the app verifies AppRelayServerName.
const relayCommonName = "rasputin-app-relay"

// relayRPCTimeout bounds one app.relay request. It only bounds that I/O
// call: a node that does not answer within it is far outside normal bounds.
const relayRPCTimeout = 15 * time.Second

// ErrNoCA is Issue's refusal when the controlplane CA did not load.
var ErrNoCA = errors.New("apprelay: no controlplane CA is loaded, so the app's relay certificate cannot be signed")

// NewIssuer refuses a nil Bus or Silence. A nil CA is not refused: the
// Issuer is always built, and refuses each Issue instead.
func NewIssuer(d IssuerDeps) (*Issuer, error) {
	switch {
	case d.Bus == nil:
		return nil, errors.New("apprelay: NewIssuer: IssuerDeps.Bus is nil")
	case d.Silence == nil:
		return nil, errors.New("apprelay: NewIssuer: IssuerDeps.Silence is nil")
	}
	return &Issuer{d: d}, nil
}

// Issue gives app its relay socket on its node: prepare (the node makes or
// reuses the app's key and returns its public half), sign (a controlplane-CA
// serverAuth leaf for AppRelayServerName over that key, expiring with the
// CA), install (the leaf and the CA alone, which opens the socket). Any
// failure returns an error and stops the later steps, so the push sends
// nothing to the node. No key ever leaves the node.
func (i *Issuer) Issue(ctx context.Context, app *apps.App) error {
	if i.d.Signer == nil || i.d.CACert == nil || len(i.d.CAPEM) == 0 {
		return ErrNoCA
	}
	ack, err := i.request(ctx, app, proto.AppRelayCmd{AppID: app.ID, Op: proto.AppRelayPrepare})
	if err != nil {
		return err
	}
	pub, err := x509.ParsePKIXPublicKey(ack.PublicKeyDER)
	if err != nil {
		return fmt.Errorf("apprelay: the relay key node %s returned for %s does not parse: %w", app.TargetNode, app.ID, err)
	}
	certPEM, err := i.d.Signer.SignLeaf(tlsca.LeafSpec{
		Usage:      tlsca.UsageServer,
		CommonName: relayCommonName,
		DNSNames:   []string{proto.AppRelayServerName},
		NotAfter:   i.d.CACert.NotAfter,
	}, pub)
	if err != nil {
		return fmt.Errorf("apprelay: sign the relay certificate of %s: %w", app.ID, err)
	}
	_, err = i.request(ctx, app, proto.AppRelayCmd{AppID: app.ID, Op: proto.AppRelayInstall, CertPEM: certPEM, CAPEM: i.d.CAPEM})
	return err
}

// Revoke removes app's relay socket from its node.
func (i *Issuer) Revoke(ctx context.Context, app *apps.App) error {
	_, err := i.request(ctx, app, proto.AppRelayCmd{AppID: app.ID, Op: proto.AppRelayRemove})
	return err
}

// request sends cmd to app's node and returns its ack, refusing an ack that
// is not OK. Silence is explained by inventory, so an agent that predates
// app.relay is named as one, with the release to update the node to.
func (i *Issuer) request(ctx context.Context, app *apps.App, cmd proto.AppRelayCmd) (proto.AppRelayAck, error) {
	payload, err := json.Marshal(cmd)
	if err != nil {
		return proto.AppRelayAck{}, fmt.Errorf("apprelay: encode %s: %w", cmd.Op, err)
	}
	subject := proto.AppRelaySubject(app.TargetNode)
	rctx, cancel := context.WithTimeout(ctx, relayRPCTimeout)
	defer cancel()
	msg, err := i.d.Bus.RequestWithContext(rctx, subject, payload)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		ictx, icancel := context.WithTimeout(context.WithoutCancel(ctx), relayRPCTimeout)
		defer icancel()
		return proto.AppRelayAck{}, fmt.Errorf("apprelay: %s the relay socket of %s: %s", cmd.Op, app.ID, i.d.Silence.ExplainNoResponder(ictx, subject))
	case err != nil:
		return proto.AppRelayAck{}, fmt.Errorf("apprelay: %s the relay socket of %s on node %s: %w", cmd.Op, app.ID, app.TargetNode, err)
	}
	var ack proto.AppRelayAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		return proto.AppRelayAck{}, fmt.Errorf("apprelay: decode the %s ack of %s: %w", cmd.Op, app.ID, err)
	}
	if !ack.OK {
		detail := ack.Detail
		if detail == "" {
			detail = "no detail"
		}
		return proto.AppRelayAck{}, fmt.Errorf("apprelay: node %s refused to %s the relay socket of %s: %s", app.TargetNode, cmd.Op, app.ID, detail)
	}
	return ack, nil
}
