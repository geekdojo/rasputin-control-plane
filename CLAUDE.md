@AGENTS.md

<!-- AGENTS.md is canonical, shared by Claude Code and Codex; Claude Code does not read it natively, so this file imports it. Add only Claude-specific notes here. -->

## Verifying authed UI pages

Authed pages are verified from screenshots: start the signed-in stack and
take them as `AGENTS.md` describes ("Verifying UI changes (authed pages)"),

```sh
scripts/identity-on-mac.sh up
scripts/identity-on-mac.sh shots /path /other-path
scripts/identity-on-mac.sh down
```

then read each `data/identity-on-mac/shots/*.png` with the Read tool. The
stack signs a synthetic fixture account in through the real sign-in; never
Bryce's account.

Claude in Chrome is for unauthenticated pages only (`/login`, `/restore`,
`/setup` on the local stack): open your own tab with `tabs_create`, never
navigate, click in or close one of Bryce's tabs, and close yours when done.
An agent never signs in through it. Never use the in-app preview browser.
