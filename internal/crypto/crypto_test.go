package crypto_test

import (
	"testing"
	"time"

	"github.com/divmora/authpin/internal/crypto"
)

func TestVault_EncryptionAndDecryption(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	vault, err := crypto.NewVault(key, "test-secret")
	if err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	raw := []byte("user@example.com")
	ciphertext, err := vault.EncryptField(raw)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	if string(ciphertext) == string(raw) {
		t.Errorf("ciphertext is plaintext")
	}

	decrypted, err := vault.DecryptField(ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if string(decrypted) != string(raw) {
		t.Errorf("expected %s, got %s", string(raw), string(decrypted))
	}
}

func TestVault_OTPHashAndVerify(t *testing.T) {
	vault, _ := crypto.NewVault("test-key", "test-secret")
	otp := "749201"

	hash := vault.HashOTP(otp)
	if !vault.VerifyOTPHash(hash, otp) {
		t.Errorf("failed to verify valid OTP")
	}

	if vault.VerifyOTPHash(hash, "000000") {
		t.Errorf("invalid OTP verified as valid")
	}
}

func TestRandomGeneration(t *testing.T) {
	otp, err := crypto.GenerateRandomOTP(6)
	if err != nil {
		t.Fatalf("failed to generate OTP: %v", err)
	}
	if len(otp) != 6 {
		t.Errorf("expected length 6, got %d (%s)", len(otp), otp)
	}

	token, err := crypto.GenerateVerificationToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if len(token) < 20 {
		t.Errorf("token too short: %s", token)
	}
}

func TestMaskRecipient(t *testing.T) {
	maskedEmail := crypto.MaskRecipient("alice@example.com")
	if maskedEmail != "a***e@example.com" {
		t.Errorf("unexpected masked email: %s", maskedEmail)
	}

	maskedPhone := crypto.MaskRecipient("+14155552671")
	if maskedPhone != "+1****71" {
		t.Errorf("unexpected masked phone: %s", maskedPhone)
	}
}

func TestVault_AttestationToken(t *testing.T) {
	vault, _ := crypto.NewVault("test-key", "test-secret")
	token, err := vault.IssueAttestationToken("alice@example.com", "login", 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue attestation token: %v", err)
	}
	if token == "" {
		t.Errorf("empty token")
	}
}
