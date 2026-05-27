package setup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed settings key/value store.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("setup: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("setup: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// Get returns the value at key, or "" if not set.
func (s *Store) Get(ctx context.Context, key string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return v, nil
}

// GetTime returns the value at key parsed as ms-since-epoch, or nil if unset.
func (s *Store) GetTime(ctx context.Context, key string) (*time.Time, error) {
	v, err := s.Get(ctx, key)
	if err != nil || v == "" {
		return nil, err
	}
	var n int64
	if _, err := fmt.Sscan(v, &n); err != nil {
		return nil, fmt.Errorf("parse %s: %w", key, err)
	}
	t := fromMs(n)
	return &t, nil
}

// Set upserts a value. The updated_at column is set automatically.
func (s *Store) Set(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at`,
		key, value, ms(time.Now().UTC()))
	return err
}

// SetTime stores a time as ms-since-epoch.
func (s *Store) SetTime(ctx context.Context, key string, t time.Time) error {
	return s.Set(ctx, key, fmt.Sprintf("%d", ms(t)))
}
