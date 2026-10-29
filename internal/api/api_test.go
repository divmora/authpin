package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/divmora/authpin/internal/api"
	"github.com/divmora/authpin/internal/crypto"
	"github.com/divmora/authpin/internal/dispatcher"
	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/service"
	"github.com/divmora/authpin/internal/storage/memory"
)

func TestAPI_GenerateAndVerifyFlow(t *testing.T) {
	vault, err := crypto.NewVault("test-master-key-32-bytes-long!", "test-jwt-secret")
	if err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	store := memory.New()
	mockEmail := dispatcher.NewMockDispatcher(model.ChannelEmail)
	routerDisp := dispatcher.NewRouter(mockEmail)

	svc := service.NewOTPService(service.Config{
		DefaultTTLSeconds: 300,
		DefaultDigits:     6,
		DefaultMaxRetries: 3,
		IssuerName:        "TestAuth",
	}, store, vault, routerDisp)

	handler := api.NewHandler(svc, store)
	router := api.NewRouter(api.RouterConfig{
		IsMultiTenant: false,
	}, handler)

	// 1. Call Generate Endpoint
	genPayload := map[string]interface{}{
		"target":      "customer@example.com",
		"channel":     "email",
		"purpose":     "login",
		"ttl_seconds": 180,
	}
	genBody, _ := json.Marshal(genPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/otp/generate", bytes.NewReader(genBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var genResp model.GenerateResponse
	if err := json.NewDecoder(w.Body).Decode(&genResp); err != nil {
		t.Fatalf("failed to decode generate response: %v", err)
	}

	if genResp.VerificationToken == "" {
		t.Fatalf("verification_token missing in response")
	}

	// Retrieve OTP delivered to mock dispatcher
	lastMsg := mockEmail.LastSent()
	if lastMsg == nil {
		t.Fatalf("mock dispatcher did not receive OTP")
	}

	// 2. Call Verify Endpoint
	verifyPayload := map[string]interface{}{
		"verification_token": genResp.VerificationToken,
		"otp":                lastMsg.OTP,
		"purpose":            "login",
	}
	verifyBody, _ := json.Marshal(verifyPayload)

	reqVerify := httptest.NewRequest(http.MethodPost, "/api/v1/otp/verify", bytes.NewReader(verifyBody))
	reqVerify.Header.Set("Content-Type", "application/json")
	wVerify := httptest.NewRecorder()
	router.ServeHTTP(wVerify, reqVerify)

	if wVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", wVerify.Code, wVerify.Body.String())
	}

	var verifyResp model.VerifyResponse
	if err := json.NewDecoder(wVerify.Body).Decode(&verifyResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}

	if !verifyResp.Success || verifyResp.Status != model.StatusVerified {
		t.Errorf("expected StatusVerified, got: %s", verifyResp.Status)
	}
}

func TestAPI_HealthCheck(t *testing.T) {
	store := memory.New()
	handler := api.NewHandler(nil, store)
	router := api.NewRouter(api.RouterConfig{IsMultiTenant: false}, handler)

	// Health
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Livez
	reqLive := httptest.NewRequest(http.MethodGet, "/livez", nil)
	wLive := httptest.NewRecorder()
	router.ServeHTTP(wLive, reqLive)
	if wLive.Code != http.StatusOK {
		t.Errorf("expected 200 for livez, got %d", wLive.Code)
	}

	// Readyz
	reqReady := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	wReady := httptest.NewRecorder()
	router.ServeHTTP(wReady, reqReady)
	if wReady.Code != http.StatusOK {
		t.Errorf("expected 200 for readyz, got %d", wReady.Code)
	}

	// Metrics
	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wMetrics := httptest.NewRecorder()
	router.ServeHTTP(wMetrics, reqMetrics)
	if wMetrics.Code != http.StatusOK {
		t.Errorf("expected 200 for metrics, got %d", wMetrics.Code)
	}
	if !bytes.Contains(wMetrics.Body.Bytes(), []byte("authpin_")) {
		t.Errorf("expected metrics output to contain 'authpin_'")
	}
}

func TestAPI_ResendAndRevoke(t *testing.T) {
	vault, _ := crypto.NewVault("test-master-key-32-bytes-long!", "test-jwt-secret")
	store := memory.New()
	mockEmail := dispatcher.NewMockDispatcher(model.ChannelEmail)
	routerDisp := dispatcher.NewRouter(mockEmail)

	svc := service.NewOTPService(service.Config{
		DefaultTTLSeconds: 300,
		DefaultDigits:     6,
		DefaultMaxRetries: 3,
		IssuerName:        "TestAuth",
	}, store, vault, routerDisp)

	handler := api.NewHandler(svc, store)
	router := api.NewRouter(api.RouterConfig{IsMultiTenant: false}, handler)

	// 1. Generate
	genPayload, _ := json.Marshal(map[string]interface{}{
		"target":  "resend-api@example.com",
		"channel": "email",
		"purpose": "login",
	})
	reqGen := httptest.NewRequest(http.MethodPost, "/api/v1/otp/generate", bytes.NewReader(genPayload))
	reqGen.Header.Set("Content-Type", "application/json")
	wGen := httptest.NewRecorder()
	router.ServeHTTP(wGen, reqGen)

	var genResp model.GenerateResponse
	_ = json.NewDecoder(wGen.Body).Decode(&genResp)

	// 2. Resend
	resendPayload, _ := json.Marshal(map[string]interface{}{
		"verification_token": genResp.VerificationToken,
	})
	reqResend := httptest.NewRequest(http.MethodPost, "/api/v1/otp/resend", bytes.NewReader(resendPayload))
	reqResend.Header.Set("Content-Type", "application/json")
	wResend := httptest.NewRecorder()
	router.ServeHTTP(wResend, reqResend)

	if wResend.Code != http.StatusOK {
		t.Fatalf("expected 200 for resend, got %d: %s", wResend.Code, wResend.Body.String())
	}

	// 3. Revoke
	revokePayload, _ := json.Marshal(map[string]interface{}{
		"verification_token": genResp.VerificationToken,
		"reason":             "user cancelled",
	})
	reqRevoke := httptest.NewRequest(http.MethodPost, "/api/v1/otp/revoke", bytes.NewReader(revokePayload))
	reqRevoke.Header.Set("Content-Type", "application/json")
	wRevoke := httptest.NewRecorder()
	router.ServeHTTP(wRevoke, reqRevoke)

	if wRevoke.Code != http.StatusOK {
		t.Fatalf("expected 200 for revoke, got %d: %s", wRevoke.Code, wRevoke.Body.String())
	}
}
