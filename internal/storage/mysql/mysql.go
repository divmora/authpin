package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/storage"
)

// Engine is the MySQL implementation of storage.StorageEngine.
type Engine struct {
	db *sql.DB
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS otp_sessions (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL DEFAULT 'default',
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    otp_hash VARCHAR(128) NOT NULL,
    recipient_encrypted BLOB NOT NULL,
    recipient_lookup_hash VARCHAR(64) NOT NULL,
    channel VARCHAR(16) NOT NULL,
    otp_type VARCHAR(16) NOT NULL DEFAULT 'numeric',
    otp_length INT NOT NULL DEFAULT 6,
    purpose VARCHAR(64) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    metadata_encrypted BLOB,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    verified_at DATETIME(6) NULL,
    INDEX idx_otp_sessions_token (token_hash),
    INDEX idx_otp_sessions_recipient (project_id, recipient_lookup_hash),
    INDEX idx_otp_sessions_cleanup (expires_at, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`

// New creates a new MySQL storage engine with connection pooling and schema migration.
func New(ctx context.Context, dsn string, maxConns int32) (*Engine, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open mysql connection: %w", err)
	}

	if maxConns > 0 {
		db.SetMaxOpenConns(int(maxConns))
	} else {
		db.SetMaxOpenConns(25)
	}
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(10 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping mysql: %w", err)
	}

	// Auto-migrate schema
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate mysql schema: %w", err)
	}

	return &Engine{db: db}, nil
}

func (e *Engine) SaveSession(ctx context.Context, session *model.OTPSession) error {
	query := `
		INSERT INTO otp_sessions (
			id, project_id, token_hash, otp_hash, recipient_encrypted,
			recipient_lookup_hash, channel, otp_type, otp_length, purpose, attempts, max_attempts,
			status, metadata_encrypted, created_at, expires_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)
	`
	_, err := e.db.ExecContext(ctx, query,
		session.ID,
		session.ProjectID,
		session.TokenHash,
		session.OTPHash,
		session.RecipientEncrypted,
		session.RecipientLookupHash,
		string(session.Channel),
		string(session.OTPType),
		session.OTPLength,
		session.Purpose,
		session.Attempts,
		session.MaxAttempts,
		string(session.Status),
		session.MetadataEncrypted,
		session.CreatedAt.UTC(),
		session.ExpiresAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to save mysql otp session: %w", err)
	}
	return nil
}

func (e *Engine) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.OTPSession, error) {
	query := `
		SELECT id, project_id, token_hash, otp_hash, recipient_encrypted,
		       recipient_lookup_hash, channel, otp_type, otp_length, purpose, attempts, max_attempts,
		       status, metadata_encrypted, created_at, expires_at, verified_at
		FROM otp_sessions
		WHERE token_hash = ?
	`
	var sess model.OTPSession
	var channelStr string
	var otpTypeStr string
	var statusStr string
	var verifiedAt sql.NullTime

	err := e.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&sess.ID,
		&sess.ProjectID,
		&sess.TokenHash,
		&sess.OTPHash,
		&sess.RecipientEncrypted,
		&sess.RecipientLookupHash,
		&channelStr,
		&otpTypeStr,
		&sess.OTPLength,
		&sess.Purpose,
		&sess.Attempts,
		&sess.MaxAttempts,
		&statusStr,
		&sess.MetadataEncrypted,
		&sess.CreatedAt,
		&sess.ExpiresAt,
		&verifiedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get mysql otp session: %w", err)
	}

	if verifiedAt.Valid {
		sess.VerifiedAt = &verifiedAt.Time
	}
	sess.Channel = model.Channel(channelStr)
	sess.OTPType = model.OTPType(otpTypeStr)
	sess.Status = model.Status(statusStr)
	return &sess, nil
}

func (e *Engine) IncrementAttempts(ctx context.Context, tokenHash string) (int, error) {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to start tx: %w", err)
	}
	defer tx.Rollback()

	updateQuery := `UPDATE otp_sessions SET attempts = attempts + 1 WHERE token_hash = ?`
	res, err := tx.ExecContext(ctx, updateQuery, tokenHash)
	if err != nil {
		return 0, fmt.Errorf("failed to update attempts: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return 0, storage.ErrSessionNotFound
	}

	var attempts int
	selectQuery := `SELECT attempts FROM otp_sessions WHERE token_hash = ?`
	if err := tx.QueryRowContext(ctx, selectQuery, tokenHash).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("failed to read updated attempts: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit tx: %w", err)
	}
	return attempts, nil
}

func (e *Engine) MarkVerified(ctx context.Context, tokenHash string, verifiedAt time.Time) error {
	query := `
		UPDATE otp_sessions
		SET status = ?, verified_at = ?
		WHERE token_hash = ? AND status = ?
	`
	res, err := e.db.ExecContext(ctx, query, string(model.StatusVerified), verifiedAt.UTC(), tokenHash, string(model.StatusPending))
	if err != nil {
		return fmt.Errorf("failed to mark session verified in mysql: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil || affected == 0 {
		return storage.ErrSessionNotFound
	}
	return nil
}

func (e *Engine) Invalidate(ctx context.Context, tokenHash string, status model.Status) error {
	query := `UPDATE otp_sessions SET status = ? WHERE token_hash = ?`
	res, err := e.db.ExecContext(ctx, query, string(status), tokenHash)
	if err != nil {
		return fmt.Errorf("failed to invalidate mysql session: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil || affected == 0 {
		return storage.ErrSessionNotFound
	}
	return nil
}

func (e *Engine) CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	query := `
		DELETE FROM otp_sessions
		WHERE expires_at < ? AND status != 'VERIFIED'
		LIMIT ?
	`
	res, err := e.db.ExecContext(ctx, query, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("failed to clean up expired sessions in mysql: %w", err)
	}
	return res.RowsAffected()
}

func (e *Engine) Ping(ctx context.Context) error {
	return e.db.PingContext(ctx)
}

func (e *Engine) Close() error {
	return e.db.Close()
}
