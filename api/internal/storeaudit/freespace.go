package storeaudit

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

const (
	// FreeSpaceAlertID is the free-space alert's stable id. #760 keeps only
	// the store's audit-blocked alert; this one is built here.
	FreeSpaceAlertID = "disk-free:data-partition"
	// FreeWarnBelow is the image's journald SystemKeepFree=4G plus 1 GiB
	// (#684 guard 1).
	FreeWarnBelow uint64 = 5 << 30
	// FreeCritBelow is two full audit footprints (2 x 512 MiB, RotateAt plus
	// KeepBytes): a judgement, not a measured floor.
	FreeCritBelow uint64 = 1 << 30
)

// FreeSpace reports low free space on the api's data partition as an alert.
// The partition holds the store, its audit log, the api's database and
// Docker, so the store refuses audited requests once it is full.
type FreeSpace struct {
	dir  string
	read func(dir string) (uint64, error)
	log  *slog.Logger
}

// NewFreeSpace returns a FreeSpace over dir. read reports the bytes available
// to an unprivileged writer (production: storage.FreeBytes).
func NewFreeSpace(dir string, read func(string) (uint64, error), log *slog.Logger) (*FreeSpace, error) {
	switch {
	case dir == "":
		return nil, errors.New("storeaudit: free-space dir is empty")
	case read == nil:
		return nil, errors.New("storeaudit: free-space read is nil")
	case log == nil:
		return nil, errors.New("storeaudit: free-space logger is nil")
	}
	return &FreeSpace{dir: dir, read: read, log: log.With("component", "storeaudit")}, nil
}

// Alerts is the alerts aggregator's source: one alert while free space is
// below FreeWarnBelow (warn) or FreeCritBelow (crit), none otherwise. A read
// that fails is a warn alert of its own: not knowing is not the same as
// having room.
func (f *FreeSpace) Alerts(now time.Time) []proto.Alert {
	free, err := f.read(f.dir)
	if err != nil {
		f.log.Warn("free space on the data partition could not be read", "file", f.dir, "err", err.Error())
		return []proto.Alert{{
			ID:       FreeSpaceAlertID,
			Severity: proto.AlertWarn,
			Source:   proto.AlertSourceNode,
			Title:    "The free space on the data partition is unknown.",
			Detail:   "The api could not read the free space on its data partition.",
			Since:    now,
		}}
	}
	if free >= FreeWarnBelow {
		return nil
	}
	a := proto.Alert{
		ID:       FreeSpaceAlertID,
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceNode,
		Title:    "The data partition is low on free space.",
		Detail: fmt.Sprintf("Only %d MiB is free on the control plane's data partition, which should keep at least %d GiB free. "+
			"When it runs out, the secret store refuses audited requests and the api cannot save its records.",
			free>>20, FreeWarnBelow>>30),
		Since: now,
	}
	if free < FreeCritBelow {
		a.Severity = proto.AlertCrit
		a.Title = "The data partition is almost full."
	}
	return []proto.Alert{a}
}
