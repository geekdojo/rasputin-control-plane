// Package gatereg holds the repo-level registers that no single package can
// check on its own, and the tests that hold the tree to them.
//
// There is no code here. Each register is a fact about the WHOLE tree —
// "every vendor behaviour we depend on is recorded against the version we
// checked it at", "every periodic tick is either a re-read of a fact or a
// bound on one I/O call" — and a check that lives inside one package can only
// ever see that package. The tests are in this package so they have one
// obvious home and one obvious place to add the next one.
//
// The registers themselves are in .github, beside the others:
//
//   - third-party-capabilities.tsv — every upstream behaviour we rely on, the
//     version it was verified at, and how. CI fails when the pinned version
//     moves without the row being re-verified (geekdojo/geekdojo-brain#496).
//   - timer-audit.tsv — every periodic tick and every credential lifetime,
//     each classified and each naming the fact behind it
//     (geekdojo/geekdojo-brain#497).
package gatereg
