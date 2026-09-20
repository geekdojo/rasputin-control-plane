package proto

// The controlplane's own agent authenticates to the bus like every other node:
// with a join token bound to its node id. The bus used to trust any connection
// from loopback instead, which let any local user on a controlplane claim any
// node's id (geekdojo/geekdojo-brain#140, decided 2026-09-17).
//
// Nobody provisions that token by hand. The api mints it for its own node id
// (RASPUTIN_SELF_NODE_ID) at every start, before it tells systemd it is ready,
// and writes it to BusAgentTokenFileName under its bus directory. The agent
// reads the file again on every connect attempt, so a token the api re-mints
// (after an identity restore, say) reaches a running agent on its next
// reconnect, with no restart.

// BusAgentTokenFileName is the controlplane agent's join token file, under the
// api's bus directory (<dataDir>/bus/, beside issuer.nk and bus.key). The file
// is one line: the plaintext token, then a newline. Owner-only (0600).
const BusAgentTokenFileName = "agent.token"

// BusAgentTokenPath is that file on an appliance, whose data dir is
// /var/lib/rasputin. A controlplane agent with no token configured reads it
// from here, so a controlplane whose node.env predates the file still joins.
const BusAgentTokenPath = "/var/lib/rasputin/bus/" + BusAgentTokenFileName

// The controlplane's own agent needs the bus PIN as well as the token, and for
// the same reason: nobody provisions it by hand. A controlplane that
// self-initialised (the bootstrap.sh path) has no seed, so its agent has no
// RASPUTIN_BUS_PIN, and before this file the only way it learned the pin was a
// bus.pin delivery over the plaintext bus — which a controlplane that starts in
// require never gets to make (geekdojo/geekdojo-brain#510).
//
// So the api writes its own live pin beside the token on every start, and its
// agent falls back to that file when nothing else gave it a pin.

// BusAgentPinFileName is the controlplane agent's pin file, under the api's bus
// directory (<dataDir>/bus/, beside agent.token). One line: the pin, then a
// newline. The pin is public, so the file is world-readable (0644).
const BusAgentPinFileName = "agent.pin"

// BusAgentPinPath is that file on an appliance, whose data dir is
// /var/lib/rasputin. A controlplane agent that was given no pin — no
// RASPUTIN_BUS_PIN and no delivered pin of its own — reads it from here.
const BusAgentPinPath = "/var/lib/rasputin/bus/" + BusAgentPinFileName
