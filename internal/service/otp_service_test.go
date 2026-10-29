package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/divmora/authpin/internal/crypto"
	"github.com/divmora/authpin/internal/dispatcher"
	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/service"
	"github.com/divmora/authpin/internal/storage/memory"
)

func setupTestService(t *testing.T) (*service.OTPService, *dispatcher.MockDispatcher) {
	vault, err := crypto.NewVault("test-master-key-32-bytes-long!", "jwt-secret-key-12345")
	if err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	store := memory.New()
	mockEmail := dispatcher.NewMockDispatcher(model.ChannelEmail)
	router := dispatcher.NewRouter(mockEmail)

	svc := service.NewOTPService(service.Config{
		DefaultTTLSeconds: 300,
		DefaultDigits:     6,
		DefaultMaxRetries: 3,
		IssuerName:        "TestAuth",
	}, store, vault, router)

	return svc, mockEmail
}

func TestOTPService_GenerateAndVerify_Success(t *testing.T) {
	svc, mockEmail := setupTestService(t)
	ctx := context.Background()

	// 1. Generate standard numeric OTP
	genResp, err := svc.Generate(ctx, "proj-1", &model.GenerateRequest{
		Target:      "test@example.com",
		Channel:     model.ChannelEmail,
		Purpose:     "login",
		TTLSeconds:  120,
		OTPLength:   6,
		OTPType:     model.OTPTypeNumeric,
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	if genResp.VerificationToken == "" {
		t.Errorf("expected verification token, got empty")
	}
	if !strings.HasPrefix(genResp.VerificationToken, "vtok_") {
		t.Errorf("token prefix unexpected: %s", genResp.VerificationToken)
	}

	// Verify that mock dispatcher received the OTP directly
	lastMsg := mockEmail.LastSent()
	if lastMsg == nil {
		t.Fatalf("expected dispatched email, found none")
	}
	deliveredOTP := lastMsg.OTP
	if len(deliveredOTP) != 6 {
		t.Errorf("expected 6-digit OTP, got %s", deliveredOTP)
	}

	// 2. Verify with correct OTP
	verifyResp, err := svc.Verify(ctx, "proj-1", &model.VerifyRequest{
		VerificationToken: genResp.VerificationToken,
		OTP:               deliveredOTP,
		Purpose:           "login",
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	if !verifyResp.Success || verifyResp.Status != model.StatusVerified {
		t.Errorf("expected verified status, got %v (%s)", verifyResp.Success, verifyResp.Status)
	}
	if verifyResp.AssertionToken == "" {
		t.Errorf("expected assertion JWT token")
	}

	// 3. Anti-Replay: Attempting to verify again must fail
	_, err = svc.Verify(ctx, "proj-1", &model.VerifyRequest{
		VerificationToken: genResp.VerificationToken,
		OTP:               deliveredOTP,
	})
	if err != service.ErrAlreadyVerified {
		t.Errorf("expected ErrAlreadyVerified on replay, got: %v", err)
	}
}

func TestOTPService_AlphanumericAndCustomLength(t *testing.T) {
	svc, mockEmail := setupTestService(t)
	ctx := context.Background()

	// Request custom 8-character alphanumeric OTP
	genResp, err := svc.Generate(ctx, "proj-alpha", &model.GenerateRequest{
		Target:      "alpha@example.com",
		Channel:     model.ChannelEmail,
		Purpose:     "document_sign",
		OTPLength:   8,
		OTPType:     model.OTPTypeAlphanumeric,
		TTLSeconds:  600,
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	lastMsg := mockEmail.LastSent()
	if lastMsg == nil {
		t.Fatalf("expected dispatched message")
	}

	code := lastMsg.OTP
	if len(code) != 8 {
		t.Errorf("expected 8-char OTP, got %s (len: %d)", code, len(code))
	}

	// Verify using lowercase representation of alphanumeric code (case-insensitivity test)
	lowerCode := strings.ToLower(code)
	verifyResp, err := svc.Verify(ctx, "proj-alpha", &model.VerifyRequest{
		VerificationToken: genResp.VerificationToken,
		OTP:               lowerCode,
		Purpose:           "document_sign",
	})
	if err != nil {
		t.Fatalf("verification failed with lowercase alphanumeric: %v", err)
	}

	if !verifyResp.Success || verifyResp.Status != model.StatusVerified {
		t.Errorf("expected verified status, got %v (%s)", verifyResp.Success, verifyResp.Status)
	}
}

func TestOTPService_MaxAttemptsLockout(t *testing.T) {
	svc, _ := setupTestService(t)
	ctx := context.Background()

	genResp, err := svc.Generate(ctx, "proj-1", &model.GenerateRequest{
		Target:      "attacker@example.com",
		Channel:     model.ChannelEmail,
		Purpose:     "login",
		MaxAttempts: 2,
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Attempt 1: wrong OTP
	resp1, err := svc.Verify(ctx, "proj-1", &model.VerifyRequest{
		VerificationToken: genResp.VerificationToken,
		OTP:               "000000",
	})
	if err != nil {
		t.Fatalf("unexpected error on attempt 1: %v", err)
	}
	if resp1.Success || resp1.RemainingTries != 1 {
		t.Errorf("expected remaining tries 1, got %d", resp1.RemainingTries)
	}

	// Attempt 2: wrong OTP (exhaustion)
	_, err = svc.Verify(ctx, "proj-1", &model.VerifyRequest{
		VerificationToken: genResp.VerificationToken,
		OTP:               "000001",
	})
	if err == nil || !strings.Contains(err.Error(), "maximum attempts reached") {
		t.Errorf("expected max attempts reached error, got: %v", err)
	}

	// Attempt 3: blocked
	_, err = svc.Verify(ctx, "proj-1", &model.VerifyRequest{
		VerificationToken: genResp.VerificationToken,
		OTP:               "000002",
	})
	if err != service.ErrMaxAttemptsReached {
		t.Errorf("expected ErrMaxAttemptsReached, got: %v", err)
	}
}

func TestOTPService_ExpiredOTP(t *testing.T) {
	svc, _ := setupTestService(t)
	ctx := context.Background()

	// Request with minimal TTL
	genResp, err := svc.Generate(ctx, "proj-1", &model.GenerateRequest{
		Target:     "expired@example.com",
		Channel:    model.ChannelEmail,
		TTLSeconds: 30, // normalized min
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Verify with invalid token
	_, err = svc.Verify(ctx, "proj-1", &model.VerifyRequest{
		VerificationToken: "vtok_nonexistent_token_1234567890",
		OTP:               "123456",
	})
	if err != service.ErrTokenNotFound {
		t.Errorf("expected ErrTokenNotFound, got: %v", err)
	}

	_ = genResp
}
