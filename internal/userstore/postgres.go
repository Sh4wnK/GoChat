package userstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/Sh4wnK/GoChat/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrate applies every embedded migration in filename order inside a
// single transaction per file.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		sql, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}

// Postgres is a userstore.Store backed by PostgreSQL via pgx.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres connects and migrates. The migrations are idempotent
// (CREATE TABLE IF NOT EXISTS), so this is safe to run on every boot.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) CreateUser(ctx context.Context, username, displayName string, passwordHash []byte) (model.User, error) {
	u := model.User{
		ID:          newID(),
		Username:    username,
		DisplayName: displayName,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO users (id, username, display_name, password) VALUES ($1, $2, $3, $4)`,
		u.ID, username, displayName, string(passwordHash))
	if err != nil {
		return model.User{}, mapPgErr(err, ErrUsernameTaken)
	}
	return u, nil
}

func (p *Postgres) GetUserByName(ctx context.Context, username string) (UserRecord, error) {
	return p.scanOne(ctx,
		`SELECT id, username, display_name, password, public_key, enabled, created_at FROM users WHERE username = $1`,
		username)
}

func (p *Postgres) GetUserByID(ctx context.Context, id string) (UserRecord, error) {
	return p.scanOne(ctx,
		`SELECT id, username, display_name, password, public_key, enabled, created_at FROM users WHERE id = $1`,
		id)
}

func (p *Postgres) scanOne(ctx context.Context, query string, arg any) (UserRecord, error) {
	row := p.pool.QueryRow(ctx, query, arg)
	var rec UserRecord
	if err := row.Scan(&rec.User.ID, &rec.User.Username, &rec.User.DisplayName,
		&rec.Password, &rec.PublicKey, &rec.Enabled, &rec.User.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRecord{}, ErrNotFound
		}
		return UserRecord{}, err
	}
	rec.User.PublicKey = rec.PublicKey
	return rec, nil
}

func (p *Postgres) ListUsers(ctx context.Context, limit, offset int) ([]model.User, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, username, display_name, public_key, created_at FROM users ORDER BY id LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PublicKey, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateProfile(ctx context.Context, id, displayName string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET display_name = $2 WHERE id = $1`, id, displayName)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) SetPublicKey(ctx context.Context, id, key string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET public_key = $2 WHERE id = $1`, id, key)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) SetEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteUser(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) EnqueueOffline(ctx context.Context, userID, messageID, payload string) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO offline_messages (user_id, message_id, payload) VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, message_id) DO NOTHING`,
		userID, messageID, payload)
	if err != nil {
		return mapPgErr(err, ErrNotFound)
	}
	return nil
}

func (p *Postgres) PopOffline(ctx context.Context, userID string) ([]string, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	rows, err := tx.Query(ctx,
		`SELECT payload FROM offline_messages WHERE user_id = $1 ORDER BY queued_at`, userID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, payload)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM offline_messages WHERE user_id = $1`, userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ids, nil
}

// newID returns a random user ID.
func newID() string { return uuid.NewString() }

func mapPgErr(err error, onUnique error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" { // unique_violation
		return onUnique
	}
	return err
}
