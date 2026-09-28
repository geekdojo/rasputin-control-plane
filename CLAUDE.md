@AGENTS.md

<!-- AGENTS.md is canonical, shared by Claude Code and Codex; Claude Code does not read it natively, so this file imports it. Add only Claude-specific notes here. -->

@~/Documents/Claude/Projects/Rasputin/CLAUDE.md

Project-wide context comes from the import above; repo instructions come from `AGENTS.md`.

## Verifying authed UI pages in a browser

Start the local stack described under "Verifying UI changes (authed pages)" in
`AGENTS.md`, then:

1. **Verify through Bryce's real Chrome** (claude-in-chrome MCP tools) — not the in-app
   preview browser, which can't hold the passkey session. **Open your own tab** with
   `tabs_create` and navigate *that* tab to `localhost:3000/...`; never navigate, click in
   or close one of his existing tabs, and close your tab when done. A new tab shares his
   Chrome's 7-day session, so the dev loop stays fully autonomous while it's valid.
   Screenshot/zoom for proof.
2. **Session expired?** Open `localhost:3000/login` in your own tab in his Chrome, click "Sign in
   with passkey" to raise the prompt, then ask Bryce for one Touch ID and wait for
   his confirmation. One tap buys another 7 days.
3. **Deployed UI** (`rasputin.local`) can be verified the same way — his Chrome
   keeps a session with the real controlplane too. Remember mutations there hit a
   real cluster.

Unauthenticated pages (`/login`, `/setup`) work fine in the preview browser directly.
