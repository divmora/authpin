package storage

import (
	"context"
	"errors"
	"time"

	"github.com/divmora/authpin/internal/model"
)

var (
	ErrSessionNotFound = errors.New("otp session not found or token invalid")
	ErrAlreadyVerified = errors.New("otp session has already been verified")
	ErrSessionExpired  = errors.New("otp session has expired")
	ErrMaxAttempts     = errors.New("maximum verification attempts exceeded")
)

// StorageEngine defines the repository contract for OTP persistence across any database backend.
type StorageEngine interface {
	// SaveSession persists a newly generated OTP session.
	SaveSession(ctx context.Context, session *model.OTPSession) error

	// GetSessionByTokenHash retrieves an active or past session by the SHA-256 hash of its verification_token.
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.OTPSession, error)

	// IncrementAttempts atomically increments the attempt counter for a session.
	IncrementAttempts(ctx context.Context, tokenHash string) (newAttempts int, err error)

	// MarkVerified transitions the session status to VERIFIED and records the timestamp.
	MarkVerified(ctx context.Context, tokenHash string, verifiedAt time.Time) error

	// Invalidate marks the session as EXHAUSTED, EXPIRED, or REVOKED.
	Invalidate(ctx context.Context, tokenHash string, status model.Status) error

	// CleanupExpired purges sessions that have expired before the given timestamp up to batch limit.
	CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error)

	// Ping checks database health.
	Ping(ctx context.Context) error

	// Close terminates any open pools or connections.
	Close() error
}
