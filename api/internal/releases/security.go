package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The security floor (geekdojo/geekdojo-brain#772): a signed OS release
// manifest may name the oldest Rasputin OS version that carries every fix for
// a reachable critical or high advisory. SecurityWatch reads it once a day
// through the job system and raises one crit alert while any OS node runs
// below it, or runs a version that could not be confirmed.
//
// The read is a job, not part of the alerts read, because every alerts read
// (the TopBar's included) would otherwise spend the release host's anonymous
// rate limit. The alert is computed on each alerts read from inventory, so it
// clears the moment the last node reports a version at or above the floor,
// with no second manifest read.

const (
	// SecurityCheckKind is the daily manifest read's workflow kind.
	SecurityCheckKind = "updates.security_check"
	// securityCheckStep is the workflow's one step.
	securityCheckStep = "read_manifest"
	// securityCheckTimeout bounds the manifest read: the release list, the
	// manifest and its signature, each one small HTTPS request.
	securityCheckTimeout = 2 * time.Minute

	// SecurityAlertID is the alert's stable id: one per watched component.
	SecurityAlertID = "security-update:os"

	securityAlertTitle = "A security update is available for Rasputin OS"
	securityAlertNext  = "Open Updates, download and stage the latest release, and deploy it."
)

// unreadableFloorMessage is the full sentence the step reports for a floor
// that is not a version, held in a value as storage and apps do for their
// user-facing error sentences.
var unreadableFloorMessage = "The newest release declares a security floor this control plane cannot read."

// errUnreadableFloor is the step's error for a floor that is not a version.
var errUnreadableFloor = errors.New(unreadableFloorMessage)

// latestFinder is the one Source operation the watch calls.
type latestFinder interface {
	LatestFor(ctx context.Context, comp Component, channel string) (*ReleaseInfo, error)
}

// nodeLister is the inventory read the alert is computed from. Satisfied by
// *inventory.Store.
type nodeLister interface {
	List(ctx context.Context) ([]*proto.Node, error)
}

// SecurityDeps are the watch's collaborators. Every field is required.
type SecurityDeps struct {
	// Source reads the newest release on Channel.
	Source latestFinder
	// Nodes reads inventory on each alerts read.
	Nodes nodeLister
	// Channel is the release channel this control plane follows.
	Channel string
	Log     *slog.Logger
	// Now stamps when a floor value was first seen.
	Now func() time.Time
}

// SecurityWatch holds the last known security floor and computes the alert
// from it.
type SecurityWatch struct {
	src     latestFinder
	nodes   nodeLister
	channel string
	comp    Component
	log     *slog.Logger
	now     func() time.Time

	// mu guards the three values the job writes while alerts reads them.
	mu sync.Mutex
	// floor is the last known floor; empty means none is known.
	floor string
	// release is the release version the floor was read from: the release
	// the operator can install on this channel.
	release string
	// since is when this floor value was first seen.
	since time.Time
}

// NewSecurityWatch builds the watch for the os component. It refuses a nil
// collaborator and a channel that is not a known one.
func NewSecurityWatch(d SecurityDeps) (*SecurityWatch, error) {
	switch {
	case d.Source == nil:
		return nil, errors.New("releases: SecurityDeps.Source is nil")
	case d.Nodes == nil:
		return nil, errors.New("releases: SecurityDeps.Nodes is nil")
	case d.Log == nil:
		return nil, errors.New("releases: SecurityDeps.Log is nil")
	case d.Now == nil:
		return nil, errors.New("releases: SecurityDeps.Now is nil")
	}
	channel, ok := ParseChannel(d.Channel)
	if !ok {
		return nil, fmt.Errorf("releases: SecurityDeps.Channel %q is not a known channel", d.Channel)
	}
	// Only the OS is watched: the store ships in the OS image.
	comp, ok := ComponentByID("os")
	if !ok {
		return nil, errors.New("releases: the os component is not registered")
	}
	return &SecurityWatch{src: d.Source, nodes: d.Nodes, channel: channel, comp: comp, log: d.Log, now: d.Now}, nil
}

// Workflow is the daily manifest read: one step, never retried inside the
// job, because the next day's job is the retry.
func (w *SecurityWatch) Workflow() jobs.Workflow {
	return jobs.Workflow{Kind: SecurityCheckKind, Steps: []jobs.WorkflowStep{{
		Name:    securityCheckStep,
		Timeout: securityCheckTimeout,
		Retries: 0,
		Do: func(sc *jobs.StepCtx) (json.RawMessage, error) {
			return nil, w.Refresh(jobs.ContextWithJobID(sc.Ctx, sc.JobID))
		},
	}}}
}

// Refresh reads the newest os manifest on the channel and records its floor.
// A failed read, or a floor that is not a version, keeps the last known floor:
// not knowing the floor is not the same as there being none. A release with no
// floor, or no release on the channel, clears it.
//
// The error it returns is the sentence a person reads on the failed job.
func (w *SecurityWatch) Refresh(ctx context.Context) error {
	jobID := jobs.JobIDFromContext(ctx)
	info, err := w.src.LatestFor(ctx, w.comp, w.channel)
	if err != nil {
		w.log.WarnContext(ctx, "release security check failed; keeping the last known floor",
			"component", w.comp.ID, "channel", w.channel, "err", err.Error(), "job_id", jobID)
		// Not wrapped (ERR-WRAP): the job-failed alert renders the step's
		// error to the operator, and the raw error names hosts and the
		// release host's vendor. It is logged in full above, under job_id.
		return errors.New(friendlyFetchError(err))
	}
	floor, release := "", ""
	if info != nil && info.Manifest.SecurityFloor != "" {
		floor, release = info.Manifest.SecurityFloor, info.Version
	}
	if floor != "" {
		if _, err := parse(w.comp.Scheme, floor); err != nil {
			w.log.WarnContext(ctx, "release security floor unreadable; keeping the last known floor",
				"component", w.comp.ID, "channel", w.channel, "release", info.Version, "floor", floor, "job_id", jobID)
			return errUnreadableFloor
		}
	}

	w.mu.Lock()
	changed := floor != w.floor
	if changed {
		w.since = w.now().UTC()
	}
	w.floor, w.release = floor, release
	w.mu.Unlock()

	if changed {
		w.log.InfoContext(ctx, "release security floor changed",
			"component", w.comp.ID, "channel", w.channel, "release", release, "floor", floor, "job_id", jobID)
	}
	return nil
}

// Alerts is the alerts aggregator's source: one crit alert while a floor is
// known and an OS node runs below it or runs an unconfirmed version, else
// none. No floor known means no alert, whatever the nodes report.
func (w *SecurityWatch) Alerts(ctx context.Context, _ time.Time) ([]proto.Alert, error) {
	w.mu.Lock()
	floor, release, since := w.floor, w.release, w.since
	w.mu.Unlock()
	if floor == "" {
		return nil, nil
	}
	nodes, err := w.nodes.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("releases: security alerts: list nodes: %w", err)
	}
	lagging := laggingNodes(nodes, w.comp, floor)
	unconfirmed := unconfirmedNodes(nodes, w.comp)
	if len(lagging) == 0 && len(unconfirmed) == 0 {
		return nil, nil
	}
	// The copy names the release that was read, never the floor: on the
	// stable channel the floor is a dev version a stable operator cannot
	// install.
	detail := []string{fmt.Sprintf("Rasputin OS %s includes a security fix.", release)}
	if len(lagging) > 0 {
		detail = append(detail, "These nodes run an older version: "+strings.Join(lagging, ", ")+".")
	}
	if len(unconfirmed) > 0 {
		detail = append(detail, "These nodes' versions could not be confirmed after their last update: "+strings.Join(unconfirmed, ", ")+".")
	}
	detail = append(detail, securityAlertNext)
	return []proto.Alert{{
		ID:       SecurityAlertID,
		Severity: proto.AlertCrit,
		Source:   proto.AlertSourceSecurity,
		Title:    securityAlertTitle,
		Detail:   strings.Join(detail, " "),
		Since:    since,
	}}, nil
}
