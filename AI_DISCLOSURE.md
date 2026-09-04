# AI-Assisted Development Disclosure

This project is developed by a human maintainer working with AI coding assistants. This
document describes how, and what that means for the code you're reading — in the spirit of
transparency policies like [NLnet's GenAI policy](https://nlnet.nl/foundation/policies/generativeAI/).

## Approach

- Development happens in interactive sessions between the maintainer and Anthropic's family
  of Claude models (Fable, Opus, etc.) via Claude Code. The specific model varies by session;
  the commit trailer below names the one used for each change.
- **Generated-content marker:** AI-assisted commits carry a
  `Co-Authored-By: Claude <model> <noreply@anthropic.com>` trailer naming the model. Commits
  without the trailer are human-authored.

## Review

Code review is itself AI-assisted in this project, so it is disclosed here rather than left
implicit in the section above.

- Where enabled, automated Claude Code workflows post review feedback on pull requests: a
  diff-scoped security review that runs on each PR, plus scheduled code-quality and
  mutation-testing sweeps that raise their own findings. Comments from these workflows are
  authored by `claude[bot]`. Which of them run in a given repository is visible in
  `.github/workflows/`.
- **This feedback is advisory and holds no merge rights.** No automation can approve or merge
  a pull request. The maintainer reads the findings, decides what to act on, and performs
  every merge.

## Human accountability

- Every AI-assisted change is reviewed by the maintainer before it lands, and the maintainer
  merges every pull request personally; CI (build, tests, vulnerability scanning where
  configured) gates pushes.
- The maintainer takes full responsibility for all published code — AI assistance does not
  dilute that accountability.
- AI-assisted code is reviewed with attention to licensing: nothing knowingly reproducing
  third-party copyrighted material is published, and everything ships under this repo's
  license.

## Provenance

Session prompts and outputs are retained privately by the maintainer; summaries are available
on reasonable request. The commit trailer identifies which commits had AI assistance and by
which model — that plus the diff is the per-change provenance record.

## Contributors

AI-assisted contributions are welcome under the same rules: disclose the assistance in your
PR, mark AI-assisted commits with a `Co-Authored-By` trailer naming the model, and review
what you submit — you are accountable for its correctness and licensing, not the tool.
