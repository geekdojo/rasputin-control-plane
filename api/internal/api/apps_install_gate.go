package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// design/storage.md §4.4's install-time gate (geekdojo/geekdojo-brain#299).
//
// A tile that declares a `critical` volume — a password vault, a photo
// library's database — may be installed while no backup target is claimed,
// but never quietly. The dialog says in plain words that the data will not
// be backed up, and install waits for an explicit acknowledgement; the api
// enforces the same rule here so the gate is not a property of one UI. What
// it deliberately is NOT is a block: a first-run user has not plugged a disk
// in yet, and refusing the install would teach them the product is broken
// rather than that their vault is unprotected. With the acknowledgement the
// install proceeds, the acknowledgement is recorded on the app (who, when),
// and the standing NO BACKUP TARGET nag — derived from the ledger, not from
// the record — stands until a target exists.
//
// `state` volumes do not gate. They are backed up too, and an installed app
// with only `state` volumes wears the same nag badge, but §4.4's gate is for
// the class whose staleness is itself harmful.

// criticalVolumes is the names of the tile's `critical` volumes, in the
// order declared. Empty means the tile has nothing the gate is for.
func criticalVolumes(tile catalog.Tile) []string {
	var out []string
	for _, v := range tile.Volumes {
		if v.Backup == tileschema.BackupCritical {
			out = append(out, v.Name)
		}
	}
	return out
}

// noBackupRefusal is the 409's sentence: it names the tile, the volume(s)
// the gate is for, what is missing (in the derivation's own words) and the
// way through — both of them, since a hard block is the wrong call.
func noBackupRefusal(tile catalog.Tile, volumes []string, reason string) string {
	noun := "volume"
	if len(volumes) > 1 {
		noun = "volumes"
	}
	return fmt.Sprintf("%s declares a critical %s (%s) and %s. Its data will not be backed up until that is fixed. "+
		"Claim a backup target first, or send acknowledgeNoBackup: true to install anyway — the app will then carry a NO BACKUP TARGET warning until a target exists.",
		tile.Name, noun, strings.Join(volumes, ", "), strings.TrimSuffix(reason, "."))
}

// noBackupGate decides whether an install of tile may proceed and, when it
// proceeds through the gate, what record to attach to the app.
//
// Returns (ack, "", nil) to proceed — ack is non-nil only when the operator
// acknowledged an actually-unconfigured cluster (an acknowledgement sent
// while backups are configured records nothing: there was nothing to
// acknowledge). Returns (nil, refusal, nil) when the install must be held
// with a 409 carrying refusal. Returns an error when the ledger could not be
// read; the caller fails the request rather than guessing.
func (s *Server) noBackupGate(ctx context.Context, tile catalog.Tile, acknowledged bool, now time.Time) (*apps.BackupAck, string, error) {
	volumes := criticalVolumes(tile)
	if len(volumes) == 0 {
		return nil, "", nil
	}
	configured, reason, err := s.backupStates.Configured(ctx)
	if err != nil {
		return nil, "", err
	}
	if configured {
		return nil, "", nil
	}
	if !acknowledged {
		return nil, noBackupRefusal(tile, volumes, reason), nil
	}
	by := ""
	if u, ok := auth.UserFromContext(ctx); ok && u != nil {
		// The user's name — what the drawer renders as "acknowledged by
		// bryce". Never the session token, never the WebAuthn handle.
		by = u.Name
	}
	return &apps.BackupAck{At: now, By: by}, "", nil
}
