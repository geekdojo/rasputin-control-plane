---
version: "0.1.2"
level: auto
processes:
  design: pair
  implementation: copilot
  testing: auto
  documentation: pair
  review: pair
  deployment: auto
---

This format is based on [AI-DECLARATION.md](https://ai-declaration.md/en/0.1.2/).

Long-form context — approach, human accountability, provenance, and the rules for
AI-assisted contributions — is in [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

## Notes

- `implementation` is declared `copilot` because the interactive sessions that produce most
  changes prompt the maintainer for permission and clarification throughout. Two scheduled
  workflows are the exception and are genuinely `auto`: `quality-sweep` and
  `mutation-survivors` run on cron, author changes and open pull requests with no human in
  the loop. Every such pull request is still reviewed and merged by the maintainer. Which
  workflows run in a given repository is visible in `.github/workflows/`.
