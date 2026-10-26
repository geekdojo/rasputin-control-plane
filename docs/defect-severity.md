# Defect severity

How to score a **bug or defect** found in this codebase: in a review, a bench run, a test
failure or an issue. It ranks the problem itself, so the person deciding what to fix next
can compare one bug with another.

> **Not event severity.** The running control plane raises alerts and events at its own
> levels: `crit`, `warn` and so on (`proto.AlertCrit`, `proto.AlertWarn`). Those describe
> what an operator should look at **now**. A defect severity describes how bad a **bug** is.
> The two are independent. An alert the product raises at `crit` can come from a Low defect,
> and a Critical defect can raise no alert at all. When you report a defect, give its
> defect severity from this page, and quote the alert level only as evidence, labelled as
> the product's level, for example "the product raises it at `crit`".

## The scale

| Defect severity | Test |
|---|---|
| **Critical** | Data loss or exposure, a broken security boundary, or a cluster that is down or can't recover without a person. |
| **High** | A core function is broken or wrong, for example the secrets store is down or a node is off the bus. A person can recover it by hand. |
| **Medium** | It works, but degraded or misleading somewhere an operator acts on it. |
| **Low** | Cosmetic, or only in history or logs. No action is needed, and the end user never sees it. |

Then adjust for **likelihood**. State how often the defect occurs, with evidence. A defect
that needs a rare combination of conditions scores lower than one every customer hits on a
normal path.

## Worked examples (2026-10-25, the #708 bench walk)

- **High:** geekdojo-brain#874. After a full disk was freed, the secrets store stayed down
  until a reboot or a manual reset.
- **High:** geekdojo-brain#875. After a restore, the control plane's own agent refused the
  restored bus key and stayed offline.
- **Low to Medium:** `node-key-changed` after a restore onto new hardware. The cluster
  recovers fine, and the end user never sees the entry. The product raises it at `crit`.
- **Low:** `job-failed` on the backup job whose own snapshot was restored. It is cosmetic.
  The product raises it at `crit`.
