package crypto_test

import (
	"testing"
	"time"

	"github.com/divmora/authpin/internal/crypto"
	"github.com/divmora/authpin/internal/model"
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

func TestGenerateOTP_NumericAndAlphanumeric(t *testing.T) {
	// 1. Numeric with custom length 8
	numOTP, err := crypto.GenerateOTP(8, model.OTPTypeNumeric)
	if err != nil {
		t.Fatalf("failed to generate numeric otp: %v", err)
	}
	if len(numOTP) != 8 {
		t.Errorf("expected length 8, got %d", len(numOTP))
	}
	for _, c := range numOTP {
		if c < '0' || c > '9' {
			t.Errorf("expected numeric digit, got: %c", c)
		}
	}

	// 2. Alphanumeric with custom length 10
	alphaOTP, err := crypto.GenerateOTP(10, model.OTPTypeAlphanumeric)
	if err != nil {
		t.Fatalf("failed to generate alphanumeric otp: %v", err)
	}
	if len(alphaOTP) != 10 {
		t.Errorf("expected length 10, got %d", len(alphaOTP))
	}

	// 3. Case-insensitive OTP verification
	vault, _ := crypto.NewVault("test-key", "test-secret")
	hash := vault.HashOTP("A7B9K2")

	// Lowercase input should match
	if !vault.VerifyOTPHash(hash, "a7b9k2") {
		t.Errorf("expected lowercase 'a7b9k2' to match hash of 'A7B9K2'")
	}
	// Uppercase input should match
	if !vault.VerifyOTPHash(hash, "A7B9K2") {
		t.Errorf("expected uppercase 'A7B9K2' to match hash of 'A7B9K2'")
	}
	// Mismatched character fails
	if vault.VerifyOTPHash(hash, "a7b9k3") {
		t.Errorf("expected mismatch to fail")
	}
}
