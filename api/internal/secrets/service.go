package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Repository is the model service the Service calls: KVRepository.
type Repository interface {
	Get(ctx context.Context, r Ref) (Secret, error)
	Write(ctx context.Context, r Ref, value secret.Value, cas int) (int, error)
	CurrentVersion(ctx context.Context, r Ref) (int, error)
	Delete(ctx context.Context, r Ref) error
}

// AppTargets answers the one app fact authorization needs: the node app appID
// is deployed to, and whether the app exists at all.
type AppTargets interface {
	TargetNode(ctx context.Context, appID string) (node string, found bool, err error)
}

// Deps is everything a Service needs. NewService refuses an incomplete one.
type Deps struct {
	Repo Repository
	Apps AppTargets
	Log  *slog.Logger
}

// Service is the business service for secrets: it authorizes every call and
// owns the create, replace and delete semantics.
type Service struct {
	repo Repository
	apps AppTargets
	log  *slog.Logger
}

// NewService checks d and returns a Service. It does no I/O.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.Repo == nil:
		return nil, errors.New("secrets: NewService: Deps.Repo is nil")
	case d.Apps == nil:
		return nil, errors.New("secrets: NewService: Deps.Apps is nil")
	case d.Log == nil:
		return nil, errors.New("secrets: NewService: Deps.Log is nil")
	}
	return &Service{repo: d.Repo, apps: d.Apps, log: d.Log}, nil
}

// The operations, as authorization and the log records name them.
const (
	opRead    = "read"
	opCreate  = "create"
	opReplace = "replace"
	opDelete  = "delete"
	opExists  = "exists"
)

// Read returns r's latest value. Only a deploy job for r's own app, on that
// app's target node, may read it: operators never read a secret back (S21).
func (s *Service) Read(ctx context.Context, a Actor, r Ref) (Secret, error) {
	if err := s.authorize(ctx, opRead, a, r); err != nil {
		return Secret{}, err
	}
	return s.repo.Get(ctx, r)
}

// Exists reports whether r is set, from its metadata alone, so no value is
// fetched. Only the reference check (CheckActor) may ask, and only about an
// app secret (geekdojo/geekdojo-brain#800). A secret that is not set is
// (false, nil); any other store failure is returned, never read as present
// or absent.
func (s *Service) Exists(ctx context.Context, a Actor, r Ref) (bool, error) {
	if err := s.authorize(ctx, opExists, a, r); err != nil {
		return false, err
	}
	if _, err := s.repo.CurrentVersion(ctx, r); err != nil {
		if errors.Is(err, secretstore.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Create sets r to value only if r is not set yet (check-and-set 0), and
// returns version 1. A secret already set is ErrExists. A value the
// environment channel cannot carry is secretstore.ErrInvalidValue, refused
// before any store call (value.go).
//
// Write order (S15 part 2, geekdojo/geekdojo-brain#765): a caller creates the
// entry before it writes the database row that references it, and refers to
// it by path, never by a KV version. A backup snapshots the database first
// and the store after, so every row it captured has its entry in the copy.
func (s *Service) Create(ctx context.Context, a Actor, r Ref, value secret.Value) (int, error) {
	if err := s.authorize(ctx, opCreate, a, r); err != nil {
		return 0, err
	}
	if err := checkDeliverable(r, value); err != nil {
		return 0, err
	}
	v, err := s.repo.Write(ctx, r, value, 0)
	if errors.Is(err, secretstore.ErrCASMismatch) {
		return 0, fmt.Errorf("%w: %s", ErrExists, r)
	}
	if err != nil {
		return 0, err
	}
	s.done(ctx, opCreate, a, r, slog.Int("version", v))
	return v, nil
}

// Replace writes value as r's next version, under check-and-set on the
// version it read first, and returns the new version. A secret that is not
// set is secretstore.ErrNotFound; a write that loses a race with another is
// ErrConflict and is never retried. Reads are latest-by-path, so a restore
// of a backup taken between a Replace and its caller's next row returns the
// replaced value (S15 part 2).
func (s *Service) Replace(ctx context.Context, a Actor, r Ref, value secret.Value) (int, error) {
	if err := s.authorize(ctx, opReplace, a, r); err != nil {
		return 0, err
	}
	if err := checkDeliverable(r, value); err != nil {
		return 0, err
	}
	cur, err := s.repo.CurrentVersion(ctx, r)
	if err != nil {
		return 0, err
	}
	v, err := s.repo.Write(ctx, r, value, cur)
	if errors.Is(err, secretstore.ErrCASMismatch) {
		return 0, fmt.Errorf("%w: %s changed after version %d was read", ErrConflict, r, cur)
	}
	if err != nil {
		return 0, err
	}
	s.done(ctx, opReplace, a, r, slog.Int("version", v))
	return v, nil
}

// Delete removes r with every version. A secret that is already absent is
// success: the end state holds either way. A caller deletes the database
// row that references r before it deletes r (S15 part 2), so no captured
// row ever names an entry the store copy lacks.
func (s *Service) Delete(ctx context.Context, a Actor, r Ref) error {
	if err := s.authorize(ctx, opDelete, a, r); err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, r); err != nil && !errors.Is(err, secretstore.ErrNotFound) {
		return err
	}
	s.done(ctx, opDelete, a, r)
	return nil
}

// authorize decides whether a may perform op on r, before any store call.
//
//   - The zero Ref, the zero Actor and every device secret are refused.
//   - An operator creates and replaces only an existing app's secrets, deletes
//     any app's (the app row may already be gone), and never reads.
//   - A deploy job reads and creates only its own app's secrets, and only for
//     that app's target node; it never replaces or deletes.
//   - The reference check asks whether an app secret exists, and nothing
//     else; nobody else asks that.
//
// An app lookup that fails refuses with its error (ERR-CLOSED).
func (s *Service) authorize(ctx context.Context, op string, a Actor, r Ref) error {
	switch {
	case !r.valid():
		s.denied(ctx, op, a, r, "the reference is the zero Ref")
		return fmt.Errorf("%w: the zero reference", ErrInvalidRef)
	case a.kind == actorNone:
		return s.forbid(ctx, op, a, r, "no actor")
	case r.kind == refDevice:
		return s.forbid(ctx, op, a, r, "device secrets have no consumer yet")
	}
	switch {
	case a.kind == actorCheck && op == opExists:
		return nil
	case a.kind == actorCheck:
		return s.forbid(ctx, op, a, r, "the reference check only asks whether a secret exists")
	case op == opExists:
		return s.forbid(ctx, op, a, r, "only the reference check asks whether a secret exists")
	}
	switch a.kind {
	case actorOperator:
		switch op {
		case opRead:
			return s.forbid(ctx, op, a, r, "secrets are write-only for operators")
		case opDelete:
			return nil
		}
		_, found, err := s.apps.TargetNode(ctx, r.owner)
		if err != nil {
			return fmt.Errorf("secrets: %s %s: looking up the app: %w", op, r, err)
		}
		if !found {
			return fmt.Errorf("%w: %s", ErrNoSuchApp, r.owner)
		}
		return nil
	case actorDeploy:
		if op != opRead && op != opCreate {
			return s.forbid(ctx, op, a, r, "a deploy job only reads and creates")
		}
		if r.owner != a.app {
			return s.forbid(ctx, op, a, r, "the secret belongs to another app")
		}
		node, found, err := s.apps.TargetNode(ctx, a.app)
		if err != nil {
			return fmt.Errorf("secrets: %s %s: looking up the app: %w", op, r, err)
		}
		if !found {
			return s.forbid(ctx, op, a, r, "the app does not exist")
		}
		if node != a.node {
			return s.forbid(ctx, op, a, r, "the node is not the app's target node")
		}
		return nil
	}
	return s.forbid(ctx, op, a, r, "unknown actor")
}

// forbid logs the refusal and returns ErrForbidden.
func (s *Service) forbid(ctx context.Context, op string, a Actor, r Ref, reason string) error {
	s.denied(ctx, op, a, r, reason)
	return fmt.Errorf("%w: %s %s: %s", ErrForbidden, op, r, reason)
}

// denied writes the one WARN record of a refusal.
func (s *Service) denied(ctx context.Context, op string, a Actor, r Ref, reason string) {
	attrs := append(s.attrs(ctx, "secrets.denied", op, a, r), slog.String("reason", reason))
	s.log.LogAttrs(ctx, slog.LevelWarn, "secret access denied", attrs...)
}

// done writes the one INFO record of a successful change.
func (s *Service) done(ctx context.Context, op string, a Actor, r Ref, extra ...slog.Attr) {
	attrs := append(s.attrs(ctx, "secrets."+op, op, a, r), extra...)
	s.log.LogAttrs(ctx, slog.LevelInfo, "secret "+op+"d", attrs...)
}

// attrs are the fields every service record carries: the component, the
// event, the operation, the reference, the actor and the job's correlation id
// (empty when the caller is not a job).
func (s *Service) attrs(ctx context.Context, event, op string, a Actor, r Ref) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("component", "secrets"),
		slog.String("event", event),
		slog.String("op", op),
		slog.String("ref", r.String()),
		slog.String("actor", a.kindName()),
	}
	switch a.kind {
	case actorOperator:
		attrs = append(attrs, slog.String("user_id", a.user))
	case actorDeploy:
		attrs = append(attrs, slog.String("app_id", a.app), slog.String("node", a.node))
	}
	return append(attrs, slog.String("job_id", jobs.JobIDFromContext(ctx)))
}
