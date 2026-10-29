package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/divmora/authpin/internal/model"
)

var (
	ErrInvalidKeySize = errors.New("master key must be 32 bytes (or 64 hex characters)")
	ErrDecryptionFail = errors.New("failed to decrypt ciphertext: authentication failed or corrupted data")
)

// Vault handles field-level encryption, OTP hashing, and token generation.
type Vault struct {
	aesGCM    cipher.AEAD
	masterKey []byte
	jwtSecret []byte
	hashSalt  []byte
}

// NewVault initializes a new cryptographic vault.
// masterKeyHex can be a 64-char hex string (32 bytes) or any pass-phrase that gets normalized via SHA-256.
func NewVault(masterKeyHex string, jwtSecret string) (*Vault, error) {
	var keyBytes []byte
	if len(masterKeyHex) == 64 {
		decoded, err := hex.DecodeString(masterKeyHex)
		if err == nil && len(decoded) == 32 {
			keyBytes = decoded
		}
	}

	if len(keyBytes) != 32 {
		// Normalize key through SHA-256 to ensure 32-byte requirement
		hash := sha256.Sum256([]byte(masterKeyHex))
		keyBytes = hash[:]
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aes init error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init error: %w", err)
	}

	// Derive hash salt from key
	saltHash := sha256.Sum256(append(keyBytes, []byte("authpin_salt_derivation")...))

	jwtBytes := []byte(jwtSecret)
	if len(jwtBytes) == 0 {
		jwtBytes = keyBytes
	}

	return &Vault{
		aesGCM:    gcm,
		masterKey: keyBytes,
		jwtSecret: jwtBytes,
		hashSalt:  saltHash[:],
	}, nil
}

// EncryptField encrypts plaintext using AES-256-GCM with a freshly generated random nonce.
func (v *Vault) EncryptField(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, v.aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	// Seal appends the ciphertext and auth tag to nonce
	ciphertext := v.aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptField decrypts ciphertext encrypted with AES-256-GCM.
func (v *Vault) DecryptField(ciphertext []byte) ([]byte, error) {
	nonceSize := v.aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecryptionFail
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := v.aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFail
	}
	return plaintext, nil
}

// HashOTP creates a keyed cryptographic hash of the raw OTP using HMAC-SHA256 with vault salt.
// It normalizes input to uppercase and trims whitespace for seamless alphanumeric comparisons.
func (v *Vault) HashOTP(otp string) string {
	normalized := strings.ToUpper(strings.TrimSpace(otp))
	mac := hmac.New(sha256.New, v.hashSalt)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyOTPHash verifies whether user-provided OTP matches the stored hash in constant time.
func (v *Vault) VerifyOTPHash(storedHash string, candidateOTP string) bool {
	expectedHash := v.HashOTP(candidateOTP)
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(expectedHash)) == 1
}

// HashToken computes a standard SHA-256 digest of the public verification token for DB indexing.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// BlindIndex creates a deterministic HMAC-SHA256 hash of a recipient identifier for rate-limiting queries.
func (v *Vault) BlindIndex(identifier string) string {
	mac := hmac.New(sha256.New, v.masterKey)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(identifier))))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateOTP generates a cryptographically secure OTP of given length and character type (numeric or alphanumeric).
func GenerateOTP(length int, otpType model.OTPType) (string, error) {
	if length < 4 {
		length = 4
	}
	if length > 32 {
		length = 32
	}

	var charset string
	if otpType == model.OTPTypeAlphanumeric {
		// Uppercase letters + digits without visually ambiguous characters (optional: standard 0-9, A-Z)
		charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	} else {
		// Default: Numeric (0-9)
		charset = "0123456789"
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		result[i] = charset[n.Int64()]
	}

	return string(result), nil
}

// GenerateRandomOTP generates a cryptographically secure numeric OTP string of given length.
// Deprecated: Use GenerateOTP(digits, model.OTPTypeNumeric) instead.
func GenerateRandomOTP(digits int) (string, error) {
	return GenerateOTP(digits, model.OTPTypeNumeric)
}

// GenerateVerificationToken generates an unguessable 32-byte random tracking token.
func GenerateVerificationToken() (string, error) {
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return "vtok_" + hex.EncodeToString(tokenBytes), nil
}

// MaskRecipient provides privacy-safe masking for emails and phone numbers.
func MaskRecipient(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "@") {
		// Email
		parts := strings.Split(target, "@")
		local := parts[0]
		domain := parts[1]
		if len(local) <= 2 {
			return string(local[0]) + "***@" + domain
		}
		return string(local[0]) + "***" + string(local[len(local)-1]) + "@" + domain
	}

	// Phone number
	if len(target) <= 4 {
		return "****"
	}
	return target[:2] + "****" + target[len(target)-2:]
}

// IssueAttestationToken signs a lightweight JWT assertion stating the verification succeeded.
func (v *Vault) IssueAttestationToken(targetMasked string, purpose string, validity time.Duration) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	now := time.Now().UTC()
	claims := map[string]interface{}{
		"iss":      "authpin",
		"sub":      targetMasked,
		"purpose":  purpose,
		"verified": true,
		"iat":      now.Unix(),
		"exp":      now.Add(validity).Unix(),
	}
	claimsBytes, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, v.jwtSecret)
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature, nil
}
