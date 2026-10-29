package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestsTotal tracks total HTTP requests partitioned by path, method, and status.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authpin",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests processed.",
		},
		[]string{"path", "method", "status"},
	)

	// HTTPRequestDuration tracks request duration latency.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "authpin",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Histogram of HTTP request durations.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		},
		[]string{"path", "method"},
	)

	// OTPGeneratedTotal counts generated OTPs.
	OTPGeneratedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authpin",
			Subsystem: "otp",
			Name:      "generated_total",
			Help:      "Total number of OTPs successfully generated and dispatched.",
		},
		[]string{"channel", "otp_type"},
	)

	// OTPVerifiedTotal counts verification attempts and outcomes.
	OTPVerifiedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authpin",
			Subsystem: "otp",
			Name:      "verified_total",
			Help:      "Total number of OTP verification attempts partitioned by outcome status.",
		},
		[]string{"status"},
	)

	// StoragePingSuccess indicates storage engine connectivity (1 = up, 0 = down).
	StoragePingSuccess = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "authpin",
			Subsystem: "storage",
			Name:      "up",
			Help:      "Storage engine connectivity status (1 = connected, 0 = disconnected).",
		},
	)
)

// RecordRequest records Prometheus metrics for an HTTP transaction.
func RecordRequest(path, method string, statusCode int, duration time.Duration) {
	HTTPRequestsTotal.WithLabelValues(path, method, strconv.Itoa(statusCode)).Inc()
	HTTPRequestDuration.WithLabelValues(path, method).Observe(duration.Seconds())
}

// RecordGenerated increments generated OTP metrics.
func RecordGenerated(channel, otpType string) {
	OTPGeneratedTotal.WithLabelValues(channel, otpType).Inc()
}

// RecordVerified increments verified OTP metrics.
func RecordVerified(status string) {
	OTPVerifiedTotal.WithLabelValues(status).Inc()
}
