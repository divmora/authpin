package memory

import (
	"context"
	"sync"
	"time"

	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/storage"
)

// Engine is an in-memory thread-safe implementation of StorageEngine.
type Engine struct {
	mu       sync.RWMutex
	sessions map[string]*model.OTPSession
}

// New creates a new in-memory storage engine.
func New() *Engine {
	return &Engine{
		sessions: make(map[string]*model.OTPSession),
	}
}

func (e *Engine) SaveSession(ctx context.Context, session *model.OTPSession) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clone to avoid accidental external mutation
	clone := *session
	e.sessions[session.TokenHash] = &clone
	return nil
}

func (e *Engine) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.OTPSession, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sess, ok := e.sessions[tokenHash]
	if !ok {
		return nil, storage.ErrSessionNotFound
	}

	clone := *sess
	return &clone, nil
}

func (e *Engine) IncrementAttempts(ctx context.Context, tokenHash string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sess, ok := e.sessions[tokenHash]
	if !ok {
		return 0, storage.ErrSessionNotFound
	}

	sess.Attempts++
	return sess.Attempts, nil
}

func (e *Engine) MarkVerified(ctx context.Context, tokenHash string, verifiedAt time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	sess, ok := e.sessions[tokenHash]
	if !ok {
		return storage.ErrSessionNotFound
	}

	sess.Status = model.StatusVerified
	sess.VerifiedAt = &verifiedAt
	return nil
}

func (e *Engine) Invalidate(ctx context.Context, tokenHash string, status model.Status) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	sess, ok := e.sessions[tokenHash]
	if !ok {
		return storage.ErrSessionNotFound
	}

	sess.Status = status
	return nil
}

func (e *Engine) CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var count int64
	for k, sess := range e.sessions {
		if sess.ExpiresAt.Before(before) {
			delete(e.sessions, k)
			count++
			if limit > 0 && int(count) >= limit {
				break
			}
		}
	}
	return count, nil
}

func (e *Engine) Ping(ctx context.Context) error {
	return nil
}

func (e *Engine) Close() error {
	return nil
}
