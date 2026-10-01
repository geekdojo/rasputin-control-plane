# The fleet-update regression net (simulated fleet)

A CI net for the fan-out **orchestration** layer: the canary gate, the bounded fan-out, the
failure budget, the per-node results grid and the verify contract, exercised together against a
whole simulated cluster. It is a **plain Go test** — no hardware to book, nothing to install
beyond the Go toolchain, about eleven seconds for the suite.

> ⚠️ **This is not the functional test [ADR-0005][adr] Decision 10 requires.** That one is a
> written plan run against a dedicated bench cluster — real nodes, real RAUC, real bootloaders
> — and it is tracked as [geekdojo-brain#80][i80]. This is [#99][i99], the cheap net underneath
> it.
>
> *"I never trust a test harness that isn't orchestrating the actual stack from top to bottom.
> We've seen that in Rasputin with almost every mock we've made. They will miss something
> critical that only shows up in real world testing."* — Bryce, 2026-08-15
>
> The record backs that. The die-after-reboot injector armed a marker where startup did not
> look, silently never fired, and returned a clean `committed` in 63 seconds. The
> `bootedSlotFromCmdline` fix would have no-opped entirely on arm64, caught only because one
> fixture came off real hardware. c08 sat *"reasoned about, not run"* for a month and then
> produced the campaign's most consequential finding.
>
> **Every scenario below was written from a bug hardware found first.** It is a ratchet, not a
> discovery tool. A green run means the specific things that once broke have not broken again;
> it does not mean a rollout will work.

For the single-node RAUC rollback scenarios against a real `rasputin-agent` process, see
[`testing-updates.md`](testing-updates.md) — a different harness answering a different question.

## Run it

From the repository root:

```bash
go test ./api/internal/updater -run TestFleetFunctional -count=1
```

- `./api/internal/updater` is the package the fan-out state machine lives in.
- `-run TestFleetFunctional` selects the twelve fleet tests by name prefix. Drop it to run the
  package's unit suite as well (also fast).
- `-count=1` disables Go's test result cache, so the tests really execute. Without it a second
  run prints `(cached)` and executes nothing.

Add `-v` to see each test name and the summary lines they log:

```bash
go test ./api/internal/updater -run TestFleetFunctional -count=1 -v
```

The suite runs on every `go test ./...`, so CI already gates on it.

## What it actually runs

Everything on the control-plane side is the shipping code:

- a real in-process NATS server and a real `nats.Conn`;
- real SQLite stores for jobs, inventory and the updater (in a per-test temp directory);
- a real `jobs.Runner` with the real `system.update` and `node.update` workflows registered, so
  the cascade submits real child jobs that run the real seven-step saga;
- the real wire events, which is what the assertions read.

Only the **nodes** are simulated. Each one is a set of NATS responders implementing the agent
side of the update protocol — precheck, download, install, reboot, `diag.health`, mark-good,
mark-bad — over a slot model, an image version and a boot identity. A simulated reboot detaches
the node's subscriptions (so the control plane sees `ErrNoResponders`, exactly as it does
against a box that is down), then re-attaches with a new boot id on the target slot.

The node behaviours are named after the bench nodes that produced them:

| Behaviour | What the node does | Expected outcome |
|---|---|---|
| `simHealthy` | takes the update | `committed` |
| `simFailDownload` | rejects the download RPC | job fails at step 3, no slot touched |
| `simFailInstall` | rejects the install RPC | job fails at step 4, still before any reboot |
| `simNoReboot` | acks the reboot, never reboots (**c13**) | `failed` — *"never rebooted: still answering on boot …"*, and **never** `rolled_back` |
| `simNeverReturns` | reboots and never comes back (**c08**) | `failed` — *"stopped answering and never came back"*, inventory left **unconfirmed** |
| `simFailHealth` | boots the new slot, fails `diag.health` | mark-bad, `rolled_back`, inventory unconfirmed |
| `simBootloaderRollback` | new boot, **old** slot | `rolled_back` — the one shape that genuinely is one |
| `simNoBootID` | pre-bootId agent | `committed` **degraded**, row flagged `unverified_boot` |

## What it does not prove

Stated plainly so a green run is not read as more than it is.

- **Nothing about RAUC, GRUB, the Pi bootloader or `/proc/cmdline`.** A simulated node reports
  what it is told to report. Agent-side backend behaviour is covered by the agent's own unit
  suites and by the bench, and **the bench stays the venue for it**.
- **Nothing about wall-clock realism.** Installs and reboots are milliseconds, and the saga's
  step timeouts are compressed by `cappedTimeouts` so the two deadline-dependent shapes (c13,
  c08) can be reached in seconds instead of five minutes each. What is asserted is the
  *behaviour* at a deadline, never the deadline's value.
- **Nothing about the HTTP surface.** The cascade is submitted through the runner, not through
  `POST /api/updates/system`, so auth, handler validation and the UI are out of scope. (This
  used to be forced: `UPDATE ALL` raised a native `confirm()` that wedged browser automation.
  It no longer does — [geekdojo-brain#95][i95] replaced it with the in-page pre-flight drawer,
  which is what makes the [#80][i80] UI-driven bench plan possible.)
- **Hardware is still the gate.** Decision 10's staging is unchanged: the bench proves a build,
  `bitscope` is the last test once or twice, and the [#80][i80] bench cluster is where a fleet
  rollout is actually *proven*. This runs between those, so a known failure cannot come back
  unnoticed.

## Sweeping the knobs

`K` (`maxInFlight`) and `maxFailures` are **owed to measurement** — see ADR-0005's revisit
criteria. The sweep makes them cheap to explore, which is not the same as settling them:
⚠️ **it measures failure CONTAINMENT only.** Simulated nodes download nothing, so whether
control-plane I/O is the binding constraint on `K` is untouched here and still owed to a bench
run ([geekdojo-brain#81][i81]). Neither default moves until both halves are in ([#97][i97]).

What it does run: a 20-node compute tier with four nodes rigged to fail, across a matrix of
`maxInFlight` × `maxFailures`, printed as a table.

It is off by default because it takes minutes rather than seconds. `RASPUTIN_FLEET_SWEEP=1` is
the environment variable that switches it on:

```bash
RASPUTIN_FLEET_SWEEP=1 go test ./api/internal/updater -run TestFleetSweep -count=1 -v 2>&1 | grep SWEEP
```

The `grep SWEEP` matters: the api logs to stderr throughout the run, so the table is otherwise
buried in it. Every table line carries that prefix for exactly this reason.

A run on 2026-08-15 (`c83739f`):

```
maxInFlight maxFailures resolved         peak   ok     failed never  wall
1           0           k=1/b=unlimited  1      16     4      0      1.21s
1           2           k=1/b=2          1      6      2      12     482ms
1           15%         k=1/b=3          1      9      3      8      724ms
2           0           k=2/b=unlimited  2      16     4      0      752ms
2           2           k=2/b=2          2      6      2      12     334ms
2           15%         k=2/b=3          2      9      3      8      421ms
4           0           k=4/b=unlimited  4      16     4      0      446ms
4           2           k=4/b=2          4      8      2      10     313ms
4           15%         k=4/b=3          4      9      3      8      307ms
8           0           k=8/b=unlimited  8      16     4      0      353ms
8           2           k=8/b=2          8      8      2      10     226ms
8           15%         k=8/b=3          8      14     4      2      338ms
25%         0           k=5/b=unlimited  5      16     4      0      400ms
25%         2           k=5/b=2          5      9      3      8      313ms
25%         15%         k=5/b=3          5      10     3      7      381ms
```

Reading it:

- **`resolved`** is what the knobs became for this tier after `ClampMaxInFlight` and
  `ResolveMaxFailures` — the numbers the cascade actually used, not the ones asked for.
- **`peak`** is the highest number of nodes simultaneously in flight, counted from the api's own
  `node_started` / `node_succeeded` / `node_failed` events. It must never exceed `resolved`; the
  sweep fails if it does.
- **`ok` / `failed` / `never`** are the grid's three outcomes: committed, red, and never started.
- ⚠️ **`wall` measures the harness, not a fleet.** Simulated installs are milliseconds and real
  ones are minutes. The times are comparable to each other *within one sweep* and to nothing
  else. What transfers is the shape — how the columns respond to the knobs.

**The interesting column is `failed` against the budget.** At `k=1` the run stops exactly at the
budget (`b=2` → 2 failures). At `k=8/b=3` it records **4**, and at `25%/b=2` it records **3**.
That overshoot is the design, not a bug: the budget stops nodes *starting* and never cancels one
already in flight, so up to `k−1` further failures can still land. The sweep is the first place
that has been *measured* rather than reasoned about, and the size of the overshoot is a direct
input to choosing `K`.

## Adding a scenario

Scenarios are small. A fleet shape, a behaviour, a spec, some assertions:

```go
func TestFleetFunctional_MyScenario(t *testing.T) {
    // 12 amd64 compute nodes; c04 will refuse its install.
    specs := behave(computeFleet(12, "amd64"), "c04", simFailInstall)
    f := newFleet(t, specs, osBundles(fleetVersion))

    run := f.run(releaseSpec(fleetVersion))       // release-keyed: the form the UI sends

    if run.Status != "failed" {
        t.Fatalf("parent job = %s; grid: %s", run.Status, formatGrid(run))
    }
    if row := run.mustOutcome("c04"); row.Outcome != proto.NodeOutcomeFailed {
        t.Errorf("c04 outcome = %q", row.Outcome)
    }
}
```

The pieces:

- `computeFleet(n, arch)` / `bitscopeShaped()` build fleet shapes; `bitscopeShaped()` is the
  24-node mixed-arch cluster (24 is `proto.MaxClusterNodes`, the largest the product admits).
- `behave(specs, id, behaviour)` returns a copy with one node's behaviour changed. It panics on
  an unknown id rather than silently doing nothing.
- `osBundles(version)` stages the two OS artifacts a mixed-arch cluster needs.
- `run.mustOutcome(id)`, `run.withOutcome(…)`, `run.changes(…)`, `run.startOrder()`,
  `run.skipReason(id)` read the report and the event stream.
- `f.nodeUpdateRow(t, run, id)` reads the durable `node_updates` row — the *ledger*, as opposed
  to the grid, which is the *report*. The two disagreeing has been a real bug more than once.
- `f.node(t, id).precheckCount()` is how "this node was never touched" is **proven** rather than
  inferred from a row the cascade wrote about it.
- `formatGrid(run)` / `formatGates(run)` render the report into a failure message, so a failing
  24-node assertion says what happened instead of sending you to the logs.

## Prove a new test can fail

⚠️ **A test that cannot fail is not a passing test.** That mistake has been made three times on
this code path, and for a ratchet it is the only thing keeping the ratchet honest — a scenario
written from a known bug proves nothing unless it still discriminates. Every assertion here was
checked against a deliberately broken copy of the product before it landed. Do the same for anything you add: break the line you think
you are covering, confirm the test goes red, then put it back.

```bash
# 1. break the thing (edit api/internal/updater/system_jobs.go, verify.go, …)
# 2. confirm the test notices
go test ./api/internal/updater -run TestFleetFunctional_MyScenario -count=1
# 3. undo it
git checkout -- api/internal/updater/system_jobs.go
```

The seven mutations used on this suite, each of which turned the named test red:

| Broken | Test that caught it |
|---|---|
| canary failure no longer aborts the run | `CanaryFailureLeavesTheFleetUntouched` |
| the fan-out semaphore is unbounded | `FanOutIsBoundedByKUnderRealSagas` |
| the failure budget always permits a start | `FailureBudgetStopsNewStarts` |
| the "answering on the prior boot" fact is latched (the #90 bug) | `C13AndC08AreToldApart` |
| conjunct (b) stops noticing a bootloader revert | `BootloaderRollbackIsTheOneRealRollback` |
| a degraded verify stops reporting its gap | `DegradedCanaryStillAuthorisesFanOut` |
| the firewall SKU filter is removed | `MixedArchFleetRollout` |

[adr]: https://github.com/geekdojo/geekdojo-brain/blob/main/projects/rasputin/adr/0005-fleet-update-strategy.md
[i80]: https://github.com/geekdojo/geekdojo-brain/issues/80
[i81]: https://github.com/geekdojo/geekdojo-brain/issues/81
[i97]: https://github.com/geekdojo/geekdojo-brain/issues/97
[i99]: https://github.com/geekdojo/geekdojo-brain/issues/99
[i95]: https://github.com/geekdojo/geekdojo-brain/issues/95
