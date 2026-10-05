package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Write-only intent secrets.
//
// A wan_config intent in PPPoE mode carries the ISP password. It follows the
// same write-only pattern as the BMC credentials (bmc.CredentialFor): the
// password is taken out of the intent's spec when the intent is written, kept
// in its own table, and is never part of what the store returns to a reader.
// It is put back only where the desired state is compiled — for the bus
// command to the firewall agent, and for the hash of that state, which has to
// match the hash the agent computes over what it applied. Nothing that is
// persisted as a job spec, step result, event or log line is derived from the
// injected form.
//
// secretField is the spec key that holds the secret on the wire from the
// browser and in the compiled UCI input. secretSetField is never stored: it is
// a read-side marker only, and is stripped on write like the secret itself.
const (
	secretField    = "secret"
	secretSetField = "secretSet"
)

// splitSecret returns spec with the secret (and any read-side marker) removed,
// and the secret it carried. Only wan_config intents carry one; every other
// kind is returned untouched. A spec that is not a JSON object is returned as
// is, for the handler's validation to refuse.
func splitSecret(kind string, spec json.RawMessage) (json.RawMessage, string, error) {
	if proto.FirewallIntentKind(kind) != proto.IntentWANConfig || len(spec) == 0 {
		return spec, "", nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(spec, &m); err != nil {
		return spec, "", nil
	}
	_, hasSecret := m[secretField]
	_, hasMarker := m[secretSetField]
	if !hasSecret && !hasMarker {
		return spec, "", nil
	}
	var secret string
	if raw, ok := m[secretField]; ok {
		if err := json.Unmarshal(raw, &secret); err != nil {
			return nil, "", fmt.Errorf("wan_config secret must be a string: %w", err)
		}
	}
	delete(m, secretField)
	delete(m, secretSetField)
	out, err := json.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	return out, secret, nil
}

// injectSecret returns spec with the secret set. Used only on the compile path.
func injectSecret(spec json.RawMessage, secret string) (json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if len(spec) > 0 {
		if err := json.Unmarshal(spec, &m); err != nil {
			return nil, fmt.Errorf("spec decode: %w", err)
		}
	}
	v, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	m[secretField] = v
	return json.Marshal(m)
}

// putSecret records an intent's secret inside tx. An empty secret leaves any
// stored one in place: a form that did not re-type the password is not asking
// to clear it.
func putSecret(ctx context.Context, tx *sql.Tx, intentID, secret string) error {
	if secret == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
        INSERT INTO firewall_intent_secrets (intent_id, secret) VALUES (?, ?)
        ON CONFLICT(intent_id) DO UPDATE SET secret = excluded.secret`,
		intentID, secret)
	return err
}

// secrets returns every stored intent secret, keyed by intent id.
func (s *Store) secrets(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT intent_id, secret FROM firewall_intent_secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, secret string
		if err := rows.Scan(&id, &secret); err != nil {
			return nil, err
		}
		out[id] = secret
	}
	return out, rows.Err()
}

// ListIntentsForCompile returns the intents with each stored secret put back
// into its spec. It is the input to Compile on the paths that dispatch the
// desired state or hash it; its result must never be returned to a reader or
// written into a job spec, step result, event or log.
func (s *Store) ListIntentsForCompile(ctx context.Context) ([]*Intent, error) {
	intents, err := s.ListIntents(ctx)
	if err != nil {
		return nil, err
	}
	secrets, err := s.secrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("read intent secrets: %w", err)
	}
	for _, in := range intents {
		secret, ok := secrets[in.ID]
		if !ok {
			continue
		}
		spec, err := injectSecret(in.Spec, secret)
		if err != nil {
			return nil, fmt.Errorf("intent %s: %w", in.ID, err)
		}
		in.Spec = spec
	}
	return intents, nil
}

// migrateInlineSecrets moves any secret still stored inside a wan_config
// spec into firewall_intent_secrets, rewriting the spec without it. Runs on
// every open: it is a no-op once nothing is inline, and it also covers a
// database restored from an archive written before the secret had its own
// table. Each row moves in its own transaction, so a failure leaves that row
// as it was and is retried on the next open.
func (s *Store) migrateInlineSecrets(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, spec FROM firewall_intents WHERE kind = ?`, string(proto.IntentWANConfig))
	if err != nil {
		return err
	}
	type pending struct {
		id     string
		spec   json.RawMessage
		secret string
	}
	var todo []pending
	for rows.Next() {
		var id, spec string
		if err := rows.Scan(&id, &spec); err != nil {
			_ = rows.Close()
			return err
		}
		stripped, secret, err := splitSecret(string(proto.IntentWANConfig), json.RawMessage(spec))
		if err != nil {
			log.Printf("firewall: intent %s: inline secret not migrated: %v", id, err)
			continue
		}
		if string(stripped) == spec {
			continue
		}
		todo = append(todo, pending{id: id, spec: stripped, secret: secret})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var errs []error
	for _, p := range todo {
		if err := s.moveSecret(ctx, p.id, p.spec, p.secret); err != nil {
			errs = append(errs, fmt.Errorf("intent %s: %w", p.id, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Store) moveSecret(ctx context.Context, id string, spec json.RawMessage, secret string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := putSecret(ctx, tx, id, secret); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE firewall_intents SET spec = ? WHERE id = ?`, string(spec), id); err != nil {
		return err
	}
	return tx.Commit()
}
