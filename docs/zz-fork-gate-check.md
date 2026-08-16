# Fork-PR gate check — temporary

Exists only to open a pull request from a fork, so the CodeQL gate's fork path
can be exercised: `upload` resolves to `never` (a fork PR has no
`security-events: write`), while the gate step itself needs no token and must
still run and enforce.

Delete this file and close the PR once the result is recorded.
