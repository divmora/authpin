package api

import (
	"net/http"
)

// RouterConfig contains configurations for routing and security.
type RouterConfig struct {
	IsMultiTenant bool
	APIKeys       map[string]string
}

// NewRouter registers endpoints with all standard middlewares.
func NewRouter(cfg RouterConfig, handler *Handler) http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/v1/otp/generate", handler.HandleGenerate)
	mux.HandleFunc("/api/v1/otp/verify", handler.HandleVerify)

	// Health check endpoints
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/healthz", handler.HandleHealth)

	// Middleware pipeline
	pipeline := Chain(
		RecoveryMiddleware,
		LoggingMiddleware,
		CORSMiddleware,
		APIKeyMiddleware(cfg.IsMultiTenant, cfg.APIKeys),
	)

	return pipeline(mux)
}
