package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	mux.HandleFunc("/api/v1/otp/resend", handler.HandleResend)
	mux.HandleFunc("/api/v1/otp/revoke", handler.HandleRevoke)

	// Health and probe endpoints
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/healthz", handler.HandleHealth)
	mux.HandleFunc("/livez", handler.HandleLive)
	mux.HandleFunc("/readyz", handler.HandleReady)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Middleware pipeline
	pipeline := Chain(
		RecoveryMiddleware,
		LoggingMiddleware,
		CORSMiddleware,
		APIKeyMiddleware(cfg.IsMultiTenant, cfg.APIKeys),
	)

	return pipeline(mux)
}
