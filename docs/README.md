# docs

Repo-local engineering notes — design decisions specific to *this* codebase, not the broader product.

For the system-level overview, see [ARCHITECTURE.md](../ARCHITECTURE.md) at the repo root.

## Testing procedures

- [testing-updates.md](testing-updates.md): one node's OS update, on a laptop, with the mock backend.
- [testing-fleet-updates.md](testing-fleet-updates.md): a whole fleet's rollout, simulated.
- [testing-storage.md](testing-storage.md): the storage backend on a bench node's real disks.
- [testing-agent-trust.md](testing-agent-trust.md): the agent's HTTPS clients against the real api leaf on the bench, and their refusal without a mesh CA bundle.
- [testing-security-resolvers.md](testing-security-resolvers.md): the lint gate over the security-setting resolvers, and the api's RP ID, origins and Secure cookie wiring, on a laptop and on the bench.
