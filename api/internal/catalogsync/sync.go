package catalogsync

import (
	"context"
	"fmt"
	"os"
)

// Sync fetches the newest published catalog and applies it if it supersedes
// what is in effect. It reports whether the catalog changed.
//
// The version is checked BEFORE the download. Skipping a fetch we would refuse
// anyway is not just a bandwidth saving: the daily poll is the common case and
// almost always a no-op, so downloading first would mean every cluster in the
// fleet pulling a bundle it discards, every day, for the life of the product.
//
// Nothing here decides trust. Sync obtains bytes; Store.Apply decides whether
// they may become the catalog, and refuses in a way that leaves the current
// catalog untouched.
func Sync(ctx context.Context, f *Fetcher, s *Store) (bool, error) {
	available, bundleURL, sigURL, err := f.Available(ctx)
	if err != nil {
		return false, s.fail(fmt.Errorf("check for a catalog: %w", err))
	}
	if available == 0 {
		// An empty release stream is a normal state on a young channel, not a
		// failure to report. The floor is doing its job.
		return false, nil
	}
	// Written as a direct comparison rather than reusing SupersedesVersion with
	// an off-by-one argument. The first draft did the clever thing, inverted the
	// comparison, and skipped every genuine update — caught by the tests below,
	// which is not a place to be clever.
	if have := s.Current().Version; available <= have {
		return false, nil
	}

	dir, err := os.MkdirTemp("", "rasputin-catalog-")
	if err != nil {
		return false, s.fail(err)
	}
	// The download is unauthenticated content on our disk until Apply verifies
	// it. It never outlives this call, whatever the outcome.
	defer os.RemoveAll(dir)

	bundlePath, sigPath, err := f.FetchInto(ctx, dir, bundleURL, sigURL)
	if err != nil {
		return false, s.fail(fmt.Errorf("download catalog v%d: %w", available, err))
	}
	if err := s.Apply(bundlePath, sigPath); err != nil {
		return false, err // Apply has already recorded the reason.
	}
	return true, nil
}
