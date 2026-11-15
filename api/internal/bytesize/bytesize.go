// Package bytesize renders byte counts for sentences a person reads.
package bytesize

import "fmt"

// Format renders n in IEC units with one decimal place: "928.0 MiB",
// "3.5 GiB". Below 1 KiB it is a whole number of bytes. Moved verbatim from
// storage's humanBytes so the updater's memory-floor sentences and storage's
// messages speak the same units (ARCH-DRY).
func Format(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
