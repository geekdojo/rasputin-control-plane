package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The re-delivery a restore kicked is written into the report AFTER the
// record — the mesh is not up when the record is written — and reads back
// with it, so the storage page can say which nodes the restored CA reached.
func TestRecordRestoreTrustRedeliveryAmendsTheReport(t *testing.T) {
	ctx := context.Background()
	st, err := OpenStore(ctx, filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now().UTC().Truncate(time.Millisecond)
	rep := &RestoreReport{ID: "r1", Phase: RestorePhase, GenerationID: "g1", PreparedAt: now, AppliedAt: &now}
	if err := st.RecordRestore(ctx, rep); err != nil {
		t.Fatalf("RecordRestore: %v", err)
	}
	got, err := st.LatestRestore(ctx)
	if err != nil || got == nil || got.TrustRedelivery != nil {
		t.Fatalf("before the kick: %+v %v (trust must be nil)", got, err)
	}

	rec := &TrustRedeliveryRecord{
		CheckedAt:     now,
		CAFingerprint: "7d9e2c78aaaa",
		Redelivered:   []string{"compute1"},
		Stale:         []string{"compute1"},
		Current:       []string{"controlplane"},
		Unreported:    []string{"fw"},
		Skipped:       map[string]int{},
	}
	if err := st.RecordRestoreTrustRedelivery(ctx, "r1", rec); err != nil {
		t.Fatalf("RecordRestoreTrustRedelivery: %v", err)
	}
	got, err = st.LatestRestore(ctx)
	if err != nil || got == nil || got.TrustRedelivery == nil {
		t.Fatalf("after the kick: %+v %v", got, err)
	}
	tr := got.TrustRedelivery
	if tr.CAFingerprint != rec.CAFingerprint || len(tr.Redelivered) != 1 || tr.Redelivered[0] != "compute1" ||
		len(tr.Unreported) != 1 || tr.Unreported[0] != "fw" || len(tr.Current) != 1 {
		t.Errorf("trust re-delivery read back wrong: %+v", tr)
	}
	// The rest of the report is untouched by the amendment.
	if got.ID != "r1" || got.GenerationID != "g1" || got.AppliedAt == nil || !got.AppliedAt.Equal(now) {
		t.Errorf("amendment disturbed the report: %+v", got)
	}
	// A second kick overwrites: it says what is true now.
	if err := st.RecordRestoreTrustRedelivery(ctx, "r1", &TrustRedeliveryRecord{CheckedAt: now, Detail: "mesh not ready"}); err != nil {
		t.Fatalf("second amendment: %v", err)
	}
	got, _ = st.LatestRestore(ctx)
	if got.TrustRedelivery == nil || got.TrustRedelivery.Detail != "mesh not ready" || len(got.TrustRedelivery.Redelivered) != 0 {
		t.Errorf("second amendment did not replace the first: %+v", got.TrustRedelivery)
	}
	if err := st.RecordRestoreTrustRedelivery(ctx, "nope", rec); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown id: err = %v, want sql.ErrNoRows", err)
	}
}
