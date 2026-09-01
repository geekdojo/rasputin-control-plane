// Package tailscale wraps the local tailscale daemon. The agent uses this
// to enroll itself in the Rasputin tailnet when the api dispatches a
// mesh.enroll command.
//
// Two backends:
//   - RealBackend shells out to the `tailscale` CLI (tailscaled must be
//     running locally; on Linux this is systemd-managed, on macOS it's
//     the Tailscale.app process).
//   - MockBackend writes its "enrolled" state to a JSON file under
//     $RASPUTIN_AGENT_STATE_DIR/tailscale/. A dev/CI fixture, and
//     EXPLICIT-ONLY: ask for it with RASPUTIN_TAILSCALE_BACKEND=mock.
//
// Autodetection: if the `tailscale` binary is on PATH, RealBackend is the
// default. If it is not, mesh join/leave is DISABLED and reported — the mock is
// never inferred, because a node that reports itself meshed when it holds no
// tailnet address is a lie the control plane will route on. See
// agent/internal/configfault.
package tailscale
