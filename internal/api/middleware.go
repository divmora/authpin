package api

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/divmora/authpin/internal/metrics"
)

type Middleware func(http.Handler) http.Handler

// Chain combines multiple middlewares into a single middleware.
func Chain(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// LoggingMiddleware logs HTTP requests with latency and method, and exports Prometheus metrics.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		metrics.RecordRequest(r.URL.Path, r.Method, rw.status, duration)
		log.Printf("[HTTP] %s %s %d %s", r.Method, r.URL.Path, rw.status, duration)
	})
}

// CORSMiddleware enables cross-origin resource sharing for web applications.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// APIKeyMiddleware validates API key if service is in multi-tenant mode.
func APIKeyMiddleware(isMultiTenant bool, validAPIKeys map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bypass health check and metrics endpoints
			if r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/livez" || r.URL.Path == "/metrics" || strings.HasPrefix(r.URL.Path, "/docs") {
				next.ServeHTTP(w, r)
				return
			}

			if !isMultiTenant {
				// Standalone mode: accept all or use default project
				next.ServeHTTP(w, r)
				return
			}

			key := r.Header.Get("X-API-Key")
			if key == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					key = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if key == "" {
				http.Error(w, `{"error":"missing api key in X-API-Key or Authorization header"}`, http.StatusUnauthorized)
				return
			}

			if len(validAPIKeys) > 0 {
				if _, ok := validAPIKeys[key]; !ok {
					http.Error(w, `{"error":"invalid or unauthorized api key"}`, http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryMiddleware catches panics and returns 500 error cleanly.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC] %v", rec)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
