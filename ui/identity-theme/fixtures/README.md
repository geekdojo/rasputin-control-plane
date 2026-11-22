# Must-fail fixtures for the theme tests

Each file here is something a test feeds to a check that must refuse it
(geekdojo/geekdojo-brain#988). None is shipped: `build.mjs` copies only
`src/login/`.

- `templates/`: TC-988-01, one template per unsafe pattern.
- `snapshot/`: TC-988-02 and TC-988-03, each added to a copy of the snapshot.
- `scan/`: TC-988-06, a base key and template text naming the engine.
