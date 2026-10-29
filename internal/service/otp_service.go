package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/divmora/authpin/internal/crypto"
	"github.com/divmora/authpin/internal/dispatcher"
	"github.com/divmora/authpin/internal/metrics"
	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/storage"
)

var (
	ErrInvalidInput       = errors.New("invalid input parameters")
	ErrTokenNotFound      = errors.New("verification token not found or invalid")
	ErrSessionExpired     = errors.New("otp session has expired")
	ErrAlreadyVerified    = errors.New("otp session already verified")
	ErrMaxAttemptsReached = errors.New("maximum verification attempts exceeded")
	ErrInvalidOTP         = errors.New("incorrect otp code")
)

type Config struct {
	DefaultTTLSeconds int
	DefaultDigits     int
	DefaultMaxRetries int
	IssuerName        string
}

type OTPService struct {
	cfg        Config
	storage    storage.StorageEngine
	vault      *crypto.Vault
	dispatcher *dispatcher.Router
}

func NewOTPService(cfg Config, store storage.StorageEngine, vault *crypto.Vault, router *dispatcher.Router) *OTPService {
	if cfg.DefaultTTLSeconds <= 0 {
		cfg.DefaultTTLSeconds = 300
	}
	if cfg.DefaultDigits <= 0 {
		cfg.DefaultDigits = 6
	}
	if cfg.DefaultMaxRetries <= 0 {
		cfg.DefaultMaxRetries = 3
	}
	if cfg.IssuerName == "" {
		cfg.IssuerName = "AuthPin"
	}

	return &OTPService{
		cfg:        cfg,
		storage:    store,
		vault:      vault,
		dispatcher: router,
	}
}

// Generate creates a cryptographically secure OTP, persists it encrypted, and delivers it to one or multiple channels simultaneously.
func (s *OTPService) Generate(ctx context.Context, projectID string, req *model.GenerateRequest) (*model.GenerateResponse, error) {
	// 1. Normalize and validate delivery targets
	targets := req.Channels
	if len(targets) == 0 && req.Target != "" && req.Channel != "" {
		targets = []model.DeliveryTarget{
			{Channel: req.Channel, Target: req.Target},
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: at least one delivery target is required (via 'channels' array or 'target' & 'channel')", ErrInvalidInput)
	}

	for _, t := range targets {
		if t.Target == "" {
			return nil, fmt.Errorf("%w: target address cannot be empty", ErrInvalidInput)
		}
		if t.Channel != model.ChannelEmail && t.Channel != model.ChannelSMS {
			return nil, fmt.Errorf("%w: unsupported channel '%s', must be 'email' or 'sms'", ErrInvalidInput, t.Channel)
		}
	}

	if req.Purpose == "" {
		req.Purpose = "verification"
	}
	if projectID == "" {
		projectID = "default"
	}

	// Dynamic TTL normalization & bounding (30s to 3600s)
	ttlSeconds := req.TTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = s.cfg.DefaultTTLSeconds
	}
	if ttlSeconds < 30 {
		ttlSeconds = 30
	}
	if ttlSeconds > 3600 {
		ttlSeconds = 3600
	}

	// Dynamic OTP Length normalization (supports both otp_length and digits alias)
	otpLength := req.OTPLength
	if otpLength <= 0 {
		otpLength = req.Digits
	}
	if otpLength <= 0 {
		otpLength = s.cfg.DefaultDigits
	}
	if otpLength < 4 {
		otpLength = 4
	}
	if otpLength > 32 {
		otpLength = 32
	}

	// OTP Type normalization: numeric | alphanumeric
	otpType := req.OTPType
	if otpType != model.OTPTypeAlphanumeric {
		otpType = model.OTPTypeNumeric
	}

	// Max retries normalization
	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = s.cfg.DefaultMaxRetries
	}

	// 2. Generate random OTP and opaque public verification token
	otpCode, err := crypto.GenerateOTP(otpLength, otpType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random otp: %w", err)
	}

	rawToken, err := crypto.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate tracking token: %w", err)
	}

	// 3. Hash & Encrypt
	tokenHash := crypto.HashToken(rawToken)
	otpHash := s.vault.HashOTP(otpCode)

	// Encrypt all delivery targets together as JSON
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to encode targets: %w", err)
	}
	recipientEncrypted, err := s.vault.EncryptField(targetsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt recipients: %w", err)
	}

	primaryTarget := targets[0].Target
	primaryChannel := targets[0].Channel
	recipientLookupHash := s.vault.BlindIndex(primaryTarget)

	var metadataEncrypted []byte
	if len(req.Metadata) > 0 {
		metaJSON, _ := json.Marshal(req.Metadata)
		metadataEncrypted, err = s.vault.EncryptField(metaJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt metadata: %w", err)
		}
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)

	sessionChannel := primaryChannel
	if len(targets) > 1 {
		sessionChannel = model.Channel("multi")
	}

	session := &model.OTPSession{
		ID:                  uuid.NewString(),
		ProjectID:           projectID,
		TokenHash:           tokenHash,
		OTPHash:             otpHash,
		RecipientEncrypted:  recipientEncrypted,
		RecipientLookupHash: recipientLookupHash,
		Channel:             sessionChannel,
		OTPType:             otpType,
		OTPLength:           otpLength,
		Purpose:             req.Purpose,
		Attempts:            0,
		MaxAttempts:         maxAttempts,
		Status:              model.StatusPending,
		MetadataEncrypted:   metadataEncrypted,
		CreatedAt:           now,
		ExpiresAt:           expiresAt,
	}

	// 4. Persist session to pluggable storage engine
	if err := s.storage.SaveSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to persist otp session: %w", err)
	}

	// 5. Dispatch OTP to ALL targets simultaneously
	ttlMinutes := (ttlSeconds + 59) / 60
	deliveries := make([]model.DeliveryResult, len(targets))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successCount int

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target model.DeliveryTarget) {
			defer wg.Done()
			dispatchReq := &dispatcher.DispatchRequest{
				Target:     target.Target,
				Channel:    target.Channel,
				OTP:        otpCode,
				Purpose:    req.Purpose,
				SenderName: s.cfg.IssuerName,
				TTLMinutes: ttlMinutes,
				Metadata:   req.Metadata,
			}
			dispatchErr := s.dispatcher.Dispatch(ctx, dispatchReq)

			mu.Lock()
			defer mu.Unlock()
			res := model.DeliveryResult{
				Channel:         target.Channel,
				RecipientMasked: crypto.MaskRecipient(target.Target),
				Success:         dispatchErr == nil,
			}
			if dispatchErr != nil {
				res.Error = dispatchErr.Error()
			} else {
				successCount++
				metrics.RecordGenerated(string(target.Channel), string(session.OTPType))
			}
			deliveries[idx] = res
		}(i, t)
	}
	wg.Wait()

	if successCount == 0 {
		// All deliveries failed; revoke session
		_ = s.storage.Invalidate(ctx, tokenHash, model.StatusRevoked)
		return nil, fmt.Errorf("failed to dispatch otp to any channel")
	}

	// 6. Return blind response (raw OTP is NEVER returned)
	return &model.GenerateResponse{
		Success:           true,
		VerificationToken: rawToken,
		Deliveries:        deliveries,
		Channel:           primaryChannel,
		RecipientMasked:   crypto.MaskRecipient(primaryTarget),
		ExpiresAt:         expiresAt,
		TTLSeconds:        ttlSeconds,
		OTPLength:         otpLength,
		OTPType:           otpType,
	}, nil
}

// Verify validates downstream input against the encrypted record and issues verification proof.
func (s *OTPService) Verify(ctx context.Context, projectID string, req *model.VerifyRequest) (*model.VerifyResponse, error) {
	if req.VerificationToken == "" {
		return nil, fmt.Errorf("%w: verification_token is required", ErrInvalidInput)
	}
	if req.OTP == "" {
		return nil, fmt.Errorf("%w: otp code is required", ErrInvalidInput)
	}

	tokenHash := crypto.HashToken(req.VerificationToken)
	session, err := s.storage.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, storage.ErrSessionNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("storage error: %w", err)
	}

	// Replay / State checks
	if session.Status == model.StatusVerified {
		metrics.RecordVerified("replay_rejected")
		return nil, ErrAlreadyVerified
	}
	if session.Status == model.StatusExhausted {
		metrics.RecordVerified("exhausted")
		return nil, ErrMaxAttemptsReached
	}
	if session.Status != model.StatusPending {
		metrics.RecordVerified("invalid_state")
		return nil, fmt.Errorf("session is in invalid state: %s", session.Status)
	}

	// Expiry check
	now := time.Now().UTC()
	if now.After(session.ExpiresAt) {
		_ = s.storage.Invalidate(ctx, tokenHash, model.StatusExpired)
		metrics.RecordVerified("expired")
		return nil, ErrSessionExpired
	}

	// Early format & length check (prevents wasting attempts on invalid lengths)
	cleanOTP := strings.TrimSpace(req.OTP)
	if session.OTPLength > 0 && len(cleanOTP) != session.OTPLength {
		return nil, fmt.Errorf("%w: expected %d characters, received %d", ErrInvalidInput, session.OTPLength, len(cleanOTP))
	}

	// Atomic attempt increment
	attempts, err := s.storage.IncrementAttempts(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to update attempts: %w", err)
	}

	if attempts > session.MaxAttempts {
		_ = s.storage.Invalidate(ctx, tokenHash, model.StatusExhausted)
		metrics.RecordVerified("exhausted")
		return nil, ErrMaxAttemptsReached
	}

	// Constant-time OTP comparison against hashed storage
	match := s.vault.VerifyOTPHash(session.OTPHash, req.OTP)
	if !match {
		remaining := session.MaxAttempts - attempts
		if remaining <= 0 {
			_ = s.storage.Invalidate(ctx, tokenHash, model.StatusExhausted)
			metrics.RecordVerified("exhausted")
			return nil, fmt.Errorf("%w: maximum attempts reached", ErrInvalidOTP)
		}
		metrics.RecordVerified("incorrect")
		return &model.VerifyResponse{
			Success:        false,
			Status:         model.StatusPending,
			Message:        "Incorrect OTP",
			AttemptsUsed:   attempts,
			RemainingTries: remaining,
		}, nil
	}

	// Successful verification: atomically transition state to VERIFIED
	if err := s.storage.MarkVerified(ctx, tokenHash, now); err != nil {
		return nil, fmt.Errorf("failed to record verification: %w", err)
	}

	metrics.RecordVerified("verified")

	// Issue signed cryptographic proof
	recipientDecrypted, _ := s.vault.DecryptField(session.RecipientEncrypted)
	var targets []model.DeliveryTarget
	maskedRecipient := ""
	if err := json.Unmarshal(recipientDecrypted, &targets); err == nil && len(targets) > 0 {
		maskedRecipient = crypto.MaskRecipient(targets[0].Target)
	} else {
		maskedRecipient = crypto.MaskRecipient(string(recipientDecrypted))
	}

	assertionToken, err := s.vault.IssueAttestationToken(maskedRecipient, session.Purpose, 15*time.Minute)
	if err != nil {
		assertionToken = ""
	}

	return &model.VerifyResponse{
		Success:        true,
		Status:         model.StatusVerified,
		Message:        "OTP verified successfully",
		AttemptsUsed:   attempts,
		VerifiedAt:     &now,
		AssertionToken: assertionToken,
	}, nil
}
