package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/divmora/authpin/internal/metrics"
	"github.com/divmora/authpin/internal/model"
	"github.com/divmora/authpin/internal/service"
	"github.com/divmora/authpin/internal/storage"
)

type Handler struct {
	svc   *service.OTPService
	store storage.StorageEngine
}

func NewHandler(svc *service.OTPService, store storage.StorageEngine) *Handler {
	return &Handler{svc: svc, store: store}
}

func (h *Handler) HandleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req model.GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	projectID := r.Header.Get("X-Project-ID")
	if projectID == "" {
		projectID = "default"
	}

	resp, err := h.svc.Generate(r.Context(), projectID, &req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req model.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	projectID := r.Header.Get("X-Project-ID")
	if projectID == "" {
		projectID = "default"
	}

	resp, err := h.svc.Verify(r.Context(), projectID, &req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenNotFound):
			writeJSONError(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, service.ErrSessionExpired):
			writeJSONError(w, err.Error(), http.StatusGone)
		case errors.Is(err, service.ErrAlreadyVerified):
			writeJSONError(w, err.Error(), http.StatusConflict)
		case errors.Is(err, service.ErrMaxAttemptsReached):
			writeJSONError(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, service.ErrInvalidOTP):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			writeJSONError(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy","service":"authpin"}`))
}

func (h *Handler) HandleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.store != nil {
		if err := h.store.Ping(r.Context()); err != nil {
			metrics.StoragePingSuccess.Set(0)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "not_ready",
				"storage": "disconnected",
				"error":   err.Error(),
			})
			return
		}
	}
	metrics.StoragePingSuccess.Set(1)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ready",
		"storage": "connected",
		"service": "authpin",
	})
}

func (h *Handler) HandleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"alive","service":"authpin"}`))
}

func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
