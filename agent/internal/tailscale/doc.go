// Package tailscale wraps the local tailscale daemon. The agent uses this
// to enroll itself in the Rasputin tailnet when the api dispatches a
// mesh.enroll command.
//
// Two backends:
//   - RealBackend shells out to the `tailscale` CLI (tailscaled must be
//     running locally; on Linux this is systemd-managed, on macOS it's
//     the Tailscale.app process).
//   - MockBackend writes its "enrolled" state to a JSON file under
//     $RASPUTIN_AGENT_STATE_DIR/tailscale/. Used when no tailscale binary
//     is present (dev machines, CI).
//
// Autodetection: if the `tailscale` binary is on PATH, RealBackend is the
// default. Force the backend via RASPUTIN_TAILSCALE_BACKEND=mock|tailscale.
package tailscale
