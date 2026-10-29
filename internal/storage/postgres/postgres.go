package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/storage"
)

// Engine is the PostgreSQL implementation of storage.StorageEngine.
type Engine struct {
	pool *pgxpool.Pool
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS otp_sessions (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL DEFAULT 'default',
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    otp_hash VARCHAR(128) NOT NULL,
    recipient_encrypted BYTEA NOT NULL,
    recipient_lookup_hash VARCHAR(64) NOT NULL,
    channel VARCHAR(16) NOT NULL,
    otp_type VARCHAR(16) NOT NULL DEFAULT 'numeric',
    purpose VARCHAR(64) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    metadata_encrypted BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ
);

ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS otp_type VARCHAR(16) NOT NULL DEFAULT 'numeric';

CREATE INDEX IF NOT EXISTS idx_otp_sessions_token_hash ON otp_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_otp_sessions_recipient ON otp_sessions(project_id, recipient_lookup_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_otp_sessions_cleanup ON otp_sessions(expires_at) WHERE status = 'PENDING';
`

// New creates a new PostgreSQL storage engine with connection pooling and executes schema migration.
func New(ctx context.Context, dsn string, maxConns int32) (*Engine, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres dsn: %w", err)
	}

	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	// Auto-migrate schema
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate postgres schema: %w", err)
	}

	return &Engine{pool: pool}, nil
}

func (e *Engine) SaveSession(ctx context.Context, session *model.OTPSession) error {
	query := `
		INSERT INTO otp_sessions (
			id, project_id, token_hash, otp_hash, recipient_encrypted,
			recipient_lookup_hash, channel, otp_type, purpose, attempts, max_attempts,
			status, metadata_encrypted, created_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)
	`
	_, err := e.pool.Exec(ctx, query,
		session.ID,
		session.ProjectID,
		session.TokenHash,
		session.OTPHash,
		session.RecipientEncrypted,
		session.RecipientLookupHash,
		string(session.Channel),
		string(session.OTPType),
		session.Purpose,
		session.Attempts,
		session.MaxAttempts,
		string(session.Status),
		session.MetadataEncrypted,
		session.CreatedAt,
		session.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save otp session: %w", err)
	}
	return nil
}

func (e *Engine) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.OTPSession, error) {
	query := `
		SELECT id, project_id, token_hash, otp_hash, recipient_encrypted,
		       recipient_lookup_hash, channel, otp_type, purpose, attempts, max_attempts,
		       status, metadata_encrypted, created_at, expires_at, verified_at
		FROM otp_sessions
		WHERE token_hash = $1
	`
	var sess model.OTPSession
	var channelStr string
	var otpTypeStr string
	var statusStr string

	err := e.pool.QueryRow(ctx, query, tokenHash).Scan(
		&sess.ID,
		&sess.ProjectID,
		&sess.TokenHash,
		&sess.OTPHash,
		&sess.RecipientEncrypted,
		&sess.RecipientLookupHash,
		&channelStr,
		&otpTypeStr,
		&sess.Purpose,
		&sess.Attempts,
		&sess.MaxAttempts,
		&statusStr,
		&sess.MetadataEncrypted,
		&sess.CreatedAt,
		&sess.ExpiresAt,
		&sess.VerifiedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get otp session: %w", err)
	}

	sess.Channel = model.Channel(channelStr)
	sess.OTPType = model.OTPType(otpTypeStr)
	sess.Status = model.Status(statusStr)
	return &sess, nil
}

func (e *Engine) IncrementAttempts(ctx context.Context, tokenHash string) (int, error) {
	query := `
		UPDATE otp_sessions
		SET attempts = attempts + 1
		WHERE token_hash = $1
		RETURNING attempts
	`
	var attempts int
	err := e.pool.QueryRow(ctx, query, tokenHash).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, storage.ErrSessionNotFound
		}
		return 0, fmt.Errorf("failed to increment attempts: %w", err)
	}
	return attempts, nil
}

func (e *Engine) MarkVerified(ctx context.Context, tokenHash string, verifiedAt time.Time) error {
	query := `
		UPDATE otp_sessions
		SET status = $1, verified_at = $2
		WHERE token_hash = $3 AND status = $4
	`
	cmdTag, err := e.pool.Exec(ctx, query, string(model.StatusVerified), verifiedAt, tokenHash, string(model.StatusPending))
	if err != nil {
		return fmt.Errorf("failed to mark session verified: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return storage.ErrSessionNotFound
	}
	return nil
}

func (e *Engine) Invalidate(ctx context.Context, tokenHash string, status model.Status) error {
	query := `
		UPDATE otp_sessions
		SET status = $1
		WHERE token_hash = $2
	`
	cmdTag, err := e.pool.Exec(ctx, query, string(status), tokenHash)
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return storage.ErrSessionNotFound
	}
	return nil
}

func (e *Engine) CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	query := `
		DELETE FROM otp_sessions
		WHERE id IN (
			SELECT id FROM otp_sessions
			WHERE expires_at < $1 AND status != 'VERIFIED'
			LIMIT $2
		)
	`
	cmdTag, err := e.pool.Exec(ctx, query, before, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to clean up expired sessions: %w", err)
	}
	return cmdTag.RowsAffected(), nil
}

func (e *Engine) Ping(ctx context.Context) error {
	return e.pool.Ping(ctx)
}

func (e *Engine) Close() error {
	e.pool.Close()
	return nil
}
