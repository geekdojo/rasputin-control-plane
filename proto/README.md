# proto

Wire schemas shared between `rasputin-api` and `rasputin-agent`.

Schemas are not yet defined. Initial decision to make when the first Job kind needs a wire schema:

- **Protobuf** — strict, codegen for Go and TypeScript, mature toolchain.
- **CUE** — schema + validation, no Go codegen (use Go structs + CUE validation), simpler to evolve.

Decision tracked in `agent-protocol.md` (to be written) in the wiki at `projects/rasputin/design/control-plane/`. In the interim, ad-hoc JSON over NATS is acceptable for scaffolding.
