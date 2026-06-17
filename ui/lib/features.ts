// Phase-gated UI feature flags. Flip a flag to true when its backing
// implementation actually ships, then remove the gate once it's permanent.

// BMC — power on/off/cycle/reset and serial-over-LAN console.
//
// There is no real BMC backend yet: the agent ships only a file-backed mock
// (real I²C / IPMI / Redfish wiring lands with the Phase 3 chassis hardware —
// see wiki design/control-plane/bmc.md). Exposing these controls today would
// let an operator "power off" or "reset" a node and have it silently no-op
// against the mock, which is worse than not offering it. So we hide every BMC
// surface until the real backend exists. Typed as `boolean` (not the literal
// `false`) so gating expressions don't read as statically dead code.
export const BMC_ENABLED: boolean = false;
