package proto

import (
	"encoding/base64"
	"fmt"
	"log/slog"
)

// The app relay (geekdojo/geekdojo-brain#1081, under the 2026-11-15 ruling on
// geekdojo/geekdojo-brain#1079 and ADR-0011). A first-party app granted a
// runtime identity gets one TLS Unix socket of its own on its node, in a
// directory the agent bind-mounts read-only into that app's containers and no
// others. A call that arrives on that socket IS that app: the agent stamps the
// app's id on it and carries it over the bus to the api, which authorizes it
// and calls the secret store with its own login. The app may create, read,
// replace and delete only its own entries under apps/<id>/_runtime/.
//
// Two bus exchanges carry it:
//
//   - api → agent, on the node's command lane: AppRelayCmd on
//     AppRelaySubject(node), to prepare, install or remove an app's socket.
//   - agent → api: AppSecretCall on AppSecretCallSubject(node), which the
//     broker lets only that node publish (rasputin.node.<id>.>). The api
//     answers with AppSecretReply on a reply subject under
//     AppSecretReplyPrefix(node), on the node's own command lane: only that
//     node may subscribe there, and no node may publish there
//     (api/internal/busauth/callout.go), so no node can forge or read another
//     node's replies.

// The relay's file contract, as an app sees it.
const (
	// AppRelayMountPath is where the app's relay directory is mounted, read
	// only, in every container of the app.
	AppRelayMountPath = "/run/rasputin/relay"
	// AppRelaySocketName is the socket's file name in that directory.
	AppRelaySocketName = "relay.sock"
	// AppRelayCAName is the controlplane CA's file name in that directory:
	// the one anchor the app verifies the socket's server certificate by.
	AppRelayCAName = "ca.pem"
	// AppRelayServerName is the name the socket's server certificate is
	// issued for, and the server name an app verifies.
	AppRelayServerName = "relay.rasputin.internal"
	// AppRelayMaxValueBytes bounds one secret value an app stores.
	AppRelayMaxValueBytes = 64 << 10
)

// AppRelayVerb is the api → agent verb that manages an app's relay socket.
// An agent that predates it has no subscription; its floor is in
// verbMinAgentVersion, so the api can tell the operator to update the node.
const AppRelayVerb = "app.relay"

// The operations of an AppRelayCmd.
const (
	// AppRelayPrepare makes, or reuses, the app's key on the node and returns
	// its public half.
	AppRelayPrepare = "prepare"
	// AppRelayInstall writes the signed certificate and the CA, and opens the
	// socket if it is not open.
	AppRelayInstall = "install"
	// AppRelayRemove closes the socket and removes the app's relay state.
	AppRelayRemove = "remove"
)

// AppRelayCmd is the request body on AppRelaySubject.
type AppRelayCmd struct {
	AppID string `json:"appId"`
	Op    string `json:"op"`
	// CertPEM and CAPEM are set on install only: the server certificate the
	// api signed over the prepared key, and the controlplane CA alone.
	CertPEM []byte `json:"certPem,omitempty"`
	CAPEM   []byte `json:"caPem,omitempty"`
}

// LogValue renders the command without its certificate bytes.
func (c AppRelayCmd) LogValue() slog.Value {
	return slog.GroupValue(slog.String("appId", c.AppID), slog.String("op", c.Op))
}

// AppRelayAck is the reply to an AppRelayCmd. PublicKeyDER is the app's
// public key, PKIX DER, on a successful prepare.
type AppRelayAck struct {
	OK           bool   `json:"ok"`
	Detail       string `json:"detail,omitempty"`
	PublicKeyDER []byte `json:"publicKeyDer,omitempty"`
}

// AppRelaySubject is the cmd subject for managing an app's relay on nodeID.
func AppRelaySubject(nodeID string) string {
	return NodeCmdSubject(nodeID, AppRelayVerb)
}

// The operations an app performs on its own runtime secrets.
const (
	AppSecretRead    = "read"
	AppSecretCreate  = "create"
	AppSecretReplace = "replace"
	AppSecretDelete  = "delete"
)

// The operations an app performs on its own Transit keys
// (geekdojo/geekdojo-brain#1084), on the same subject and reply lane as its
// runtime secrets. Value carries the input: on encrypt the plaintext as
// standard base64, on decrypt Transit's vault:v<N>:<base64> ciphertext. The
// reply's Value carries the output: the ciphertext, or the plaintext as
// standard base64.
const (
	AppKeyCreate  = "key.create"
	AppKeyEncrypt = "key.encrypt"
	AppKeyDecrypt = "key.decrypt"
	AppKeyDestroy = "key.destroy"
)

// AppKeyMaxPlaintextBytes bounds one plaintext an app encrypts, decoded. Its
// largest ciphertext, with a 10-digit key version, is
// len("vault:v")+10+1 + 4*ceil((12+32768+16)/3) = 43,746 characters, under
// AppRelayMaxValueBytes, so whatever the relay accepts to encrypt it accepts
// back to decrypt (F-1084-03).
const AppKeyMaxPlaintextBytes = 32 << 10

// AppKeyPlaintextFits reports whether b64, standard padded base64, decodes to
// at most AppKeyMaxPlaintextBytes. It counts from the length and padding
// alone, so the agent and the api bound the same input the same way; whether
// b64 is valid base64 is the api's check.
func AppKeyPlaintextFits(b64 string) bool {
	n := base64.StdEncoding.DecodedLen(len(b64))
	for i := len(b64) - 1; i >= 0 && i >= len(b64)-2 && b64[i] == '='; i-- {
		n--
	}
	return n <= AppKeyMaxPlaintextBytes
}

// AppSecretCall is one call an app made on its relay socket, as the agent
// carries it to the api. AppID is the app the socket belongs to, stamped by
// the agent and never read from the app's request.
type AppSecretCall struct {
	AppID string `json:"appId"`
	Op    string `json:"op"`
	Name  string `json:"name"`
	// Value is set on create and replace, and on a key's encrypt and
	// decrypt.
	Value string `json:"value,omitempty"`
}

// LogValue renders the call without its value.
func (c AppSecretCall) LogValue() slog.Value {
	return slog.GroupValue(slog.String("appId", c.AppID), slog.String("op", c.Op), slog.String("name", c.Name))
}

// The stable codes of an AppSecretReply, and of an error body the agent
// writes on the socket (ERR-BOUNDARY).
const (
	AppSecretOK          = "ok"
	AppSecretNotFound    = "not_found"
	AppSecretExists      = "exists"
	AppSecretConflict    = "conflict"
	AppSecretForbidden   = "forbidden"
	AppSecretInvalid     = "invalid"
	AppSecretUnavailable = "unavailable"
	// AppSecretTooLarge and AppSecretMethodNotAllowed are the agent's own
	// refusals; the api never sends them.
	AppSecretTooLarge         = "too_large"
	AppSecretMethodNotAllowed = "method_not_allowed"
)

// AppSecretReply is the api's answer to an AppSecretCall. Message is a
// sentence safe to hand the app; CorrelationID names the api's log record of
// the call. Value is set on a successful read, encrypt or decrypt only.
type AppSecretReply struct {
	Code          string `json:"code"`
	Message       string `json:"message,omitempty"`
	CorrelationID string `json:"correlationId"`
	Value         string `json:"value,omitempty"`
}

// LogValue renders the reply without its value.
func (r AppSecretReply) LogValue() slog.Value {
	return slog.GroupValue(slog.String("code", r.Code), slog.String("message", r.Message),
		slog.String("correlationId", r.CorrelationID))
}

// AppSecretCallSubject is where nodeID's agent publishes an app's call.
func AppSecretCallSubject(nodeID string) string {
	return fmt.Sprintf("rasputin.node.%s.relay.app.secret", nodeID)
}

// AppSecretCallFilter is the api's subscription to every node's app calls.
const AppSecretCallFilter = "rasputin.node.*.relay.app.secret"

// AppSecretReplyPrefix is the prefix of every reply subject nodeID's agent
// asks the api to answer on: under the node's own command lane, which only
// that node may subscribe to and no node may publish on. It ends in a dot;
// the agent appends a unique token.
func AppSecretReplyPrefix(nodeID string) string {
	return NodeCmdSubject(nodeID, AppRelayVerb+".reply.")
}

// AppSecretCallNode takes the node id back out of a subject built by
// AppSecretCallSubject. ok is false for any other shape. Node ids carry no
// dots, so the id is exactly the one segment between the prefix and suffix.
func AppSecretCallNode(subject string) (nodeID string, ok bool) {
	const prefix, suffix = "rasputin.node.", ".relay.app.secret"
	if len(subject) <= len(prefix)+len(suffix) || subject[:len(prefix)] != prefix || subject[len(subject)-len(suffix):] != suffix {
		return "", false
	}
	nodeID = subject[len(prefix) : len(subject)-len(suffix)]
	for i := 0; i < len(nodeID); i++ {
		if nodeID[i] == '.' || nodeID[i] == '*' || nodeID[i] == '>' {
			return "", false
		}
	}
	return nodeID, true
}
