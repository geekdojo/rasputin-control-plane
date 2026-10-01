# docs

Repo-local engineering notes — design decisions specific to *this* codebase, not the broader product.

For the system-level overview, see [ARCHITECTURE.md](../ARCHITECTURE.md) at the repo root.

## Testing procedures

- [testing-updates.md](testing-updates.md): one node's OS update, on a laptop, with the mock backend.
- [testing-fleet-updates.md](testing-fleet-updates.md): a whole fleet's rollout, simulated.
- [testing-security-resolvers.md](testing-security-resolvers.md): the lint gate over the security-setting resolvers, and the api's RP ID, origins and Secure cookie wiring, on a laptop.
- [testing-collector-trust.md](testing-collector-trust.md): the Alloy probe, which runs the pinned Alloy image against a local TLS server to prove collector trust, on a laptop.
