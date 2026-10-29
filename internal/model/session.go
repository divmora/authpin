package model

import (
	"time"
)

// Channel defines the communication channel for OTP delivery.
type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelSMS   Channel = "sms"
)

// OTPType defines the character set structure for generated OTPs.
type OTPType string

const (
	OTPTypeNumeric      OTPType = "numeric"
	OTPTypeAlphanumeric OTPType = "alphanumeric"
)

// Status represents the lifecycle status of an OTP session.
type Status string

const (
	StatusPending   Status = "PENDING"
	StatusVerified  Status = "VERIFIED"
	StatusExhausted Status = "EXHAUSTED"
	StatusExpired   Status = "EXPIRED"
	StatusRevoked   Status = "REVOKED"
)

// OTPSession represents the persisted OTP session record.
type OTPSession struct {
	ID                  string            `json:"id"`
	ProjectID           string            `json:"project_id"`
	TokenHash           string            `json:"token_hash"`            // SHA-256 of the verification_token
	OTPHash             string            `json:"otp_hash"`              // Argon2id or HMAC-SHA256 salted hash of raw OTP
	RecipientEncrypted  []byte            `json:"recipient_encrypted"`   // AES-256-GCM encrypted recipient (email or phone)
	RecipientLookupHash string            `json:"recipient_lookup_hash"` // Blind HMAC-SHA256 index for rate-limiting
	Channel             Channel           `json:"channel"`
	OTPType             OTPType           `json:"otp_type"`              // numeric or alphanumeric
	Purpose             string            `json:"purpose"`
	Attempts            int               `json:"attempts"`
	MaxAttempts         int               `json:"max_attempts"`
	Status              Status            `json:"status"`
	MetadataEncrypted   []byte            `json:"metadata_encrypted,omitempty"` // AES-256-GCM encrypted metadata JSON
	MetadataPlain       map[string]string `json:"-"`                            // Decrypted in-memory representation
	CreatedAt           time.Time         `json:"created_at"`
	ExpiresAt           time.Time         `json:"expires_at"`
	VerifiedAt          *time.Time        `json:"verified_at,omitempty"`
}

// GenerateRequest defines the payload for creating and delivering a new OTP.
type GenerateRequest struct {
	Target      string            `json:"target"`                 // Email or phone number
	Channel     Channel           `json:"channel"`                // "email" or "sms"
	Purpose     string            `json:"purpose"`                // e.g. "login", "password_reset", "transaction"
	Digits      int               `json:"digits,omitempty"`       // Deprecated: use OTPLength
	OTPLength   int               `json:"otp_length,omitempty"`  // Custom OTP length (min: 4, max: 32, default: 6)
	OTPType     OTPType           `json:"otp_type,omitempty"`    // "numeric" | "alphanumeric" (default: "numeric")
	TTLSeconds  int               `json:"ttl_seconds,omitempty"`  // Dynamic expiry in seconds (default: 300)
	MaxAttempts int               `json:"max_attempts,omitempty"` // Max allowed retries (default: 3)
	Metadata    map[string]string `json:"metadata,omitempty"`     // Audit metadata (IP, user agent, tenant ID)
}

// GenerateResponse is returned to downstream systems upon successful generation and dispatch.
type GenerateResponse struct {
	Success           bool      `json:"success"`
	VerificationToken string    `json:"verification_token"` // Tracking hash passed downstream
	Channel           Channel   `json:"channel"`
	RecipientMasked   string    `json:"recipient_masked"`
	ExpiresAt         time.Time `json:"expires_at"`
	TTLSeconds        int       `json:"ttl_seconds"`
}

// VerifyRequest is submitted by downstream systems to validate user-supplied OTP.
type VerifyRequest struct {
	VerificationToken string `json:"verification_token"` // The tracking token returned during generation
	OTP               string `json:"otp"`                // User-supplied numeric code
	Purpose           string `json:"purpose,omitempty"`  // Optional purpose check
}

// VerifyResponse is returned after validation.
type VerifyResponse struct {
	Success         bool       `json:"success"`
	Status          Status     `json:"status"`
	Message         string     `json:"message"`
	AttemptsUsed    int        `json:"attempts_used"`
	RemainingTries  int        `json:"remaining_tries,omitempty"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	AssertionToken  string     `json:"assertion_token,omitempty"` // Signed JWT verification proof
}
