// Command rasputin-catalog-verify checks an app-catalog bundle against its
// detached CMS signature, using the SAME verifier the api uses at runtime:
// catalogsync.NewVerifier, bound to the catalog signing purpose.
//
// WHY THIS EXISTS. scripts/embed-catalog.sh used to verify with
//
//	openssl cms -verify ... -CAfile root-ca.pem -purpose any
//
// at build time and in CI. `-purpose any` was not laziness — a catalog leaf
// carries the catalog purpose OID and deliberately NOT codeSigning, so
// openssl's default S/MIME purpose check rejects it on that basis alone, and
// the script had no way to ask openssl about a private OID. But "any purpose"
// is the whole authorization question answered with a shrug: the check that
// remained was chain-to-root, which the RELEASE leaf also satisfies. A catalog
// signed with the release leaf embedded cleanly, and the split ADR-0006
// Decision 3 rests on was not enforced at the one point where a catalog is
// baked into every image built from the commit.
//
// The Go verifier can ask the question openssl could not, and it is the same
// code path the running api applies to a catalog fetched over the network — so
// the floor is admitted under the rule the fleet enforces, rather than a looser
// one that happened to be expressible in a shell script.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
)

func main() {
	catalog := flag.String("catalog", "", "path to the catalog bundle (catalog.json)")
	sig := flag.String("sig", "", "path to its detached CMS signature (catalog.json.sig)")
	rootCA := flag.String("root-ca", "", "path to the Rasputin root CA PEM to verify against")
	flag.Parse()

	missing := ""
	switch {
	case *catalog == "":
		missing = "-catalog"
	case *sig == "":
		missing = "-sig"
	case *rootCA == "":
		missing = "-root-ca"
	}
	if missing != "" {
		fmt.Fprintf(os.Stderr, "rasputin-catalog-verify: %s is required\n", missing)
		flag.Usage()
		os.Exit(2)
	}

	if err := catalogsync.NewVerifier(*rootCA).VerifyForPurpose(*catalog, *sig); err != nil {
		fmt.Fprintf(os.Stderr, "rasputin-catalog-verify: %s does not verify as an app-catalog bundle: %v\n",
			*catalog, err)
		os.Exit(1)
	}
	fmt.Printf("ok: %s verifies against %s under the app-catalog signing purpose\n", *catalog, *rootCA)
}
