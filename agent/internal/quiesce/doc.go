// Package quiesce is the agent side of design/storage.md §4.3 — the drivers
// that make a copy of an app volume safe to take — and §4.7's staged copy that
// the §4.5 fan-out will consume.
//
// One verb: storage.backup_stage_volume. Given a volume, its backup class and
// its quiesce strategy, produce a CONSISTENT copy under the agent's staging
// root as one tar file with a known length and a digest, and put the app back
// exactly as it was found. One companion verb, storage.backup_unstage, deletes
// a staged file by name so the fan-out can hold §4.7's "one volume at a time"
// peak. And the inverse, storage.backup_restore_volume (restore.go): fetch the
// plaintext tar the api unsealed, unpack it beside the volume, and — with the
// app quiesced under the same restart guard — exchange it for the live tree
// in one move (#291 phase 2).
//
// # What is built, and what is deliberately not
//
// The 2026-09-02 classification (geekdojo-brain #293) declares, across 35
// volumes: 24 `stop`, 10 `none`, one `sqlite` (homeassistant-config), and
// ZERO `postgres` or `mysql` — immich-db and romm-db both take `stop`,
// because dumping a database while its sibling upload volume keeps being
// written produces an archive whose rows and files disagree. So this package
// implements three strategies and REFUSES the other two by name. A driver
// nothing exercises is a driver nothing tests; a future tile that declares
// `postgres` fails its first backup with the volume named in the refusal
// rather than being silently skipped.
//
// # Consistency, per strategy — what each copy is, and the window it leaves
//
//   - stop: every container in the app's compose project is stopped (kept, not
//     removed; sixty seconds' grace before a kill), the volume is copied from
//     the host, the containers are started again. The copy is CLEAN-SHUTDOWN
//     consistent: every file is as the app left it, and all agree with each
//     other. Window: none. Cost: the app is down for the length of a local
//     disk copy, measured and reported as DowntimeMillis.
//   - sqlite: every SQLite database in the volume (found by header, not by a
//     declared path — see below) is snapshotted through the RUNNING app's own
//     container, then everything else in the volume is copied live. Each
//     database is transactionally consistent as of its snapshot; each other
//     file is whatever it was when the copy reached it. Window: a non-database
//     file rewritten during the copy may be torn, and the databases and the
//     rest of the volume can disagree by the length of the copy. The app
//     stays up.
//   - none: a plain copy while the app may be writing. Window: the whole copy.
//     Only right where the tile declared that nothing writes the volume while
//     the app runs — which is what §4.2's `cache` and `bulk` volumes are, and
//     neither is staged here at all.
//
// A `stop` or `sqlite` volume whose app is NOT running when the command
// arrives is copied plainly — nothing writes a stopped app's volume, so that
// copy is clean-shutdown consistent for free — and the app is deliberately
// NOT started afterwards. Restoring service means restoring the state the app
// was found in; an operator who stopped an app did not ask a backup to start
// it.
//
// # The sqlite gap, closed
//
// §4.3 defines the sqlite driver as acting on "the declared DB paths". The
// tile schema declares no paths, and the one `sqlite` volume is MIXED:
// homeassistant-config holds the recorder database and `.storage/`, which
// holds auth tokens and the device registry. A driver that copied only the
// databases would lose the credential half silently, and the operator would
// find out on restore day. So this driver finds databases by their file
// header (`SQLite format 3\0`), snapshots each, and captures every other file
// in the volume — the `-wal`/`-shm`/`-journal` siblings of a snapshotted
// database excepted, because the snapshot is self-contained and those would
// be incoherent with it. The ack lists which paths were snapshots.
//
// Ordering: snapshots first, then the live walk. The databases are the
// fast-changing half (the recorder writes continuously), so taking them at
// one instant and then walking the slow half bounds how far the two can
// drift to the walk's duration.
//
// The snapshot runs INSIDE a running container that mounts the volume, so it
// takes the database's locks the way the app does. The pinned Home Assistant
// image ships no `sqlite3` binary and does ship `python3` with the sqlite3
// module (probed 2026-09-02), so the runtime tries the CLI's VACUUM INTO and
// then the module's Online Backup API, and the ack names which ran.
//
// # The restart contract (§4.7), and how it is held
//
// "The agent's container restart is unconditional and entirely local. A
// watchdog armed at stop time fires regardless of upload outcome, api
// reachability, or any remote state."
//
// The `stop` driver arms a guard BEFORE it stops anything. The guard is a
// goroutine that restarts the app when released or when a deadline passes,
// whichever comes first, using its own background context — never the
// request's, which may already be cancelled. The driver releases it in a
// defer, so it runs on success, on failure, on a panic and on a cancelled
// context; the reply to the api is composed afterwards and the restart does
// not wait for it. If the process itself dies, a marker written before the
// stop is swept at the next agent start and the app started then. Nothing on
// this path consults the api, the bus, or the upload.
//
// A restart that fails is retried with backoff, in the background past the
// reply if need be, and the ack says AppRestored=false — which the fan-out
// must treat as louder than a failed backup, because it is worse than one.
//
// # The copy never follows a symlink
//
// This process is root on the host and reads the host-side mountpoint of a
// volume whose container may be running. A compromised app can plant a
// symlink in its own volume — swap a file for a link to /etc/shadow or the
// mesh CA key between the walk seeing it and the copy opening it, swap a
// directory for a link to /, or plant one in the scratch directory the
// snapshot is written to, which the container controls outright. So the
// walk is directory-fd relative with O_NOFOLLOW on every component, every
// opened fd is fstat'd and required to be what the walk said it was, and
// sizes come from the opened fd. A symlink anywhere in a path is a refusal,
// never a redirect; a symlink that was there all along is archived as a
// symlink. The snapshot substitute is opened beneath the same root the same
// way, so what the container wrote there is read only if it is a regular
// file reachable without following a link. See tarwalk.go and walk_unix.go.
//
// # Staging discipline (§4.7)
//
// Same root as the write verb (storage.StagingRoot — one derivation, the
// agent's), so there is one directory to budget, sweep and exclude. A
// source-side free-space guard refuses before anything is written: the volume
// plus its snapshots plus proto.BackupStagingReserveBytes must fit. One volume
// is staged at a time. The tar is written to a dot-prefixed partial name and
// renamed into place, so a crash leaves a file the boot sweep removes and
// never a half-written file under a name the api will ask for.
//
// # What is out of scope here
//
// `bulk` volumes stream direct (§4.7) and are refused by this verb; the
// direct stream is geekdojo-brain #295's transport work. Moving a staged file
// off the node is likewise #295 and #296. Choosing WHEN to stop an app the
// operator is using — a Minecraft server drops its players, a vault is
// seconds — is the fan-out's; this package reports ServiceInterrupting and
// the measured downtime so it can.
//
// Mock: the docker mock (RASPUTIN_DOCKER_BACKEND=mock, explicit only, never
// autodetected) models volumes as directories and stop/start as persisted
// state; the drivers' filesystem code runs unchanged against it.
package quiesce
