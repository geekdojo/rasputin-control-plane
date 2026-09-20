package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Bus join-token management. The plaintext token is returned exactly once at
// mint time (like mesh preauth keys); thereafter only secret-free metadata is
// listable. One token is not revocable at all: the one the api minted for this
// controlplane's own agent, which the list marks `selfAgent` (#140). Agents present a token as NATS username=node-id, password=token;
// the auth-callout responder validates it. See internal/busauth.

func (s *Server) handleListBusTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.busTokens.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []busauth.TokenInfo{}
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleMintBusToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label  string `json:"label"`
		NodeID string `json:"nodeId"` // required: the node id the token is bound to
		// Role is the node role the token is for. Optional only because the
		// Add-node wizard has always sent the role as the label; one of the
		// two must name a role (busauth.ResolveRole).
		Role proto.NodeRole `json:"role"`
		// SSHAuthorizedKey is the operator public key to put in this node's
		// seed. Optional: omitted means the saved operator key (the wizard's
		// prefill), and an explicit empty string means no key at all — a
		// console/UI-only node, which is a valid choice. Public-key material
		// only; nothing here is a secret.
		SSHAuthorizedKey *string `json:"sshAuthorizedKey,omitempty"`
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Every token is bound to one node (geekdojo-brain#423): there is no
	// unbound mint, because an unbound token authenticated as whatever node id
	// the connecting client chose. The id must also be one the bus will accept
	// as a username; a token bound to anything else could never authenticate.
	// Rejected, not normalized, so the id the operator sees is the id the node
	// presents.
	if body.NodeID == "" {
		writeError(w, http.StatusBadRequest, "nodeId is required: every join token is bound to the node id it will authenticate as")
		return
	}
	if !busauth.ValidNodeID(body.NodeID) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid nodeId %q: %s", body.NodeID, busauth.NodeIDRule))
		return
	}

	// Every token is bound to the role of the node it is for (busauth role.go):
	// the bus refuses a token that names none, so minting one would hand the
	// operator a seed that can never join. The controlplane's role is not
	// mintable here: the only controlplane token is the one the api mints for
	// its own agent at start.
	role, err := busauth.ResolveRole(body.Role, body.Label)
	if err != nil {
		writeError(w, http.StatusBadRequest, "role is required: every join token is bound to the role of the node it is for — send role (one of firewall, compute, storage); "+err.Error())
		return
	}
	if role == proto.RoleControlPlane {
		writeError(w, http.StatusBadRequest, "role controlplane cannot be minted: the controlplane's own agent token is minted by the api at start")
		return
	}

	// REFUSED while bus TLS is unavailable (geekdojo/geekdojo-brain#510). The
	// seed rendered below carries RASPUTIN_BUS_PIN, and with no bus key there
	// is no pin to put in it. A node seeded without one
	// comes up unpinned and stays that way: it dials plaintext, and the only
	// route back is a pin delivery this controlplane cannot make until its own
	// key is fixed. Minting nothing is the recoverable failure.
	if s.busTLS == nil {
		writeError(w, http.StatusServiceUnavailable, "refusing to mint a join token: "+busTLSUnavailable+
			", so the seed would carry no bus pin and the node would join unencrypted and stay that way. "+
			"Fix or restore the bus key (bus/bus.key in the api's data directory, /var/lib/rasputin on an appliance) and restart the api, then mint the token.")
		return
	}

	// Cluster-size cap (proto.MaxClusterNodes): refuse a mint that would
	// commit a NEW prospective node past the cap. Committed = live nodes +
	// pending enrollments (bound, unrevoked tokens whose node hasn't
	// registered). A re-mint for an id that's already live or pending is a
	// token replacement, not growth, and is always allowed.
	// Registration is the backstop for anything that slips past this.
	grows, used, err := s.mintGrowsCluster(r.Context(), body.NodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if grows && used >= proto.MaxClusterNodes {
		writeError(w, http.StatusConflict, fmt.Sprintf(
			"cluster is at the %d-node cap (%d nodes + pending enrollments); remove a node or revoke a pending token first",
			proto.MaxClusterNodes, used))
		return
	}

	plaintext, id, err := s.busTokens.MintBound(r.Context(), body.Label, body.NodeID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The SEED is rendered here, by the one renderer (proto.RenderSeed,
	// methodology §5.6 and §7 4.2). The UI used to render its own copy from
	// this response, with its own idea of which values needed quoting and its
	// own default cluster name; a UI-minted seed and a CLI-provisioned one
	// could differ, and did (control-plane #70, and a missing cluster id that
	// silently bound a UI-enrolled firewall to the wrong cluster).
	sshKey, err := s.seedSSHKey(r.Context(), body.SSHAuthorizedKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	seed, err := proto.RenderSeed(proto.Seed{
		Role:      role,
		NodeID:    body.NodeID,
		ClusterID: s.setup.ClusterID(),
		NATSURL:   proto.NATSURLFor(s.setup.ClusterHostname()),
		JoinToken: plaintext,
		// The pin comes from the same response as the token, so a seed can
		// never pair a token with a pin read at another moment (#448).
		BusPin:           s.busPin(),
		SSHAuthorizedKey: sshKey,
		Origin:           "the Rasputin control plane",
	})
	if err != nil {
		// The token is already minted, so this is not a 4xx the caller can
		// retry away: it is a control plane that cannot describe its own
		// cluster. Say so rather than returning a response with no seed and
		// letting the wizard show a blank box.
		writeError(w, http.StatusInternalServerError, "the join token was minted but its seed could not be rendered: "+err.Error())
		return
	}
	// token is returned ONCE — the operator seeds it into the node and it's
	// unrecoverable afterward. busPin rides along for callers that predate
	// the rendered seed and still assemble their own.
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":     id,
		"label":  body.Label,
		"nodeId": body.NodeID,
		"role":   string(role),
		"token":  plaintext,
		"busPin": s.busPin(),
		"seed":   seed,
	})
}

// seedSSHKey resolves the operator public key a minted seed carries.
//
// nil (the field absent) means "whatever is saved" — the wizard's prefill, and
// what every caller that does not care should send. A non-nil value is the
// operator's choice for THIS node, including an explicit empty string, which
// is a console/UI-only node and a valid answer.
//
// A non-empty value is checked by setup.ValidOperatorSSHKey — the one
// operator-SSH-key rule (geekdojo/geekdojo-brain#545). A key the wizard would
// accept and this endpoint would refuse, or the reverse, is a cluster
// provisioned two ways from one keyboard.
func (s *Server) seedSSHKey(ctx context.Context, requested *string) (string, error) {
	if requested == nil {
		ok, err := s.setup.OperatorSSHKey(ctx)
		if err != nil {
			return "", fmt.Errorf("read the saved operator SSH key: %w", err)
		}
		return ok.Key, nil
	}
	key := strings.TrimSpace(*requested)
	if key == "" {
		return "", nil
	}
	if !setup.ValidOperatorSSHKey(key) {
		return "", fmt.Errorf("sshAuthorizedKey is %w", setup.ErrInvalidSSHKey)
	}
	return key, nil
}

// mintGrowsCluster reports whether minting a token bound to nodeID would
// commit a new prospective node, and
// returns the committed count: live nodes plus distinct pending enrollments
// (bound, unrevoked tokens whose node id isn't in inventory). Mirrors the
// UI's pending-bay accounting so the API and the wizard agree on "full".
func (s *Server) mintGrowsCluster(ctx context.Context, nodeID string) (grows bool, used int, err error) {
	nodes, err := s.inv.List(ctx)
	if err != nil {
		return false, 0, err
	}
	live := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		live[n.ID] = true
	}
	tokens, err := s.busTokens.List(ctx)
	if err != nil {
		return false, 0, err
	}
	pending := make(map[string]bool)
	for _, t := range tokens {
		if t.RevokedAt != nil || t.NodeID == nil || *t.NodeID == "" {
			continue
		}
		if !live[*t.NodeID] {
			pending[*t.NodeID] = true
		}
	}
	used = len(nodes) + len(pending)
	grows = !live[nodeID] && !pending[nodeID]
	return grows, used, nil
}

func (s *Server) handleRevokeBusToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing token id")
		return
	}
	disconnected, err := s.busTokens.Revoke(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "no live token with that id")
			return
		}
		// The controlplane's own agent token (geekdojo-brain#140). 409, not
		// 403: the request is well-formed and the caller is authorised — the
		// state of this particular token is what makes it refusable, and the
		// same conflict answers the UI's "cancel this pending enrollment",
		// which is this route too. The message says what to do instead.
		if errors.Is(err, busauth.ErrSelfAgentToken) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Revoke also closed every live bus session the token authenticated
	// (certificates.md §4.2(1)). Say how many: an operator revoking a token in
	// response to a compromise needs to know whether a live session was cut,
	// and "0" is a real answer (the node was offline) rather than a silence.
	if disconnected > 0 {
		log.Printf("rasputin-api: revoked bus token %q and closed %d live bus connection(s)", id, disconnected)
	}
	writeJSON(w, http.StatusOK, revokeBusTokenResponse{ID: id, Disconnected: disconnected})
}

// revokeBusTokenResponse is DELETE /api/bus/tokens/{id}'s reply.
type revokeBusTokenResponse struct {
	ID string `json:"id"`
	// Disconnected is how many live bus connections authenticated with the
	// token were closed by the revoke. Their reconnects are refused.
	Disconnected int `json:"disconnected"`
}
