// Package middleware provides HTTP observability middleware for CyberSiren
// services, including Prometheus request metrics and OpenTelemetry trace
// propagation. It is designed for use with the shared httputil server.
package middleware

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	httputil "github.com/saif/cybersiren/shared/http"
)

// HTTPMetrics holds Prometheus collectors for HTTP request instrumentation.
type HTTPMetrics struct {
	RequestsTotal  *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
}

// RegisterHTTPMetrics creates, registers, and returns HTTP metrics collectors
// on the given Prometheus registry. The metrics are labelled by method, path,
// and status code.
func RegisterHTTPMetrics(reg *prometheus.Registry, serviceName string) *HTTPMetrics {
	m := &HTTPMetrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "http_requests_total",
			Help:        "Total number of HTTP requests.",
			ConstLabels: prometheus.Labels{"service": serviceName},
		}, []string{"method", "path", "status"}),

		RequestLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:        "http_request_duration_seconds",
			Help:        "HTTP request latency in seconds.",
			ConstLabels: prometheus.Labels{"service": serviceName},
			Buckets:     prometheus.DefBuckets,
		}, []string{"method", "path", "status"}),
	}

	reg.MustRegister(m.RequestsTotal, m.RequestLatency)
	return m
}

// Metrics returns middleware that records Prometheus HTTP request metrics.
func Metrics(m *HTTPMetrics) httputil.MiddlewareFunc {
	return func(ctx httputil.Context) {
		start := time.Now()
		path := ctx.Request().URL.Path
		method := ctx.Request().Method

		ctx.Next()

		status := responseStatus(ctx)
		statusStr := strconv.Itoa(status)
		elapsed := time.Since(start).Seconds()

		m.RequestsTotal.WithLabelValues(method, path, statusStr).Inc()
		m.RequestLatency.WithLabelValues(method, path, statusStr).Observe(elapsed)
	}
}

// Tracing returns middleware that creates an OpenTelemetry span for each
// inbound HTTP request and propagates the trace context from request headers.
func Tracing(serviceName string) httputil.MiddlewareFunc {
	tracer := otel.Tracer(serviceName + "/http")
	propagator := otel.GetTextMapPropagator()

	return func(ctx httputil.Context) {
		r := ctx.Request()
		savedCtx := r.Context()

		// Extract parent span from inbound headers.
		carrier := propagation.HeaderCarrier(r.Header)
		parentCtx := propagator.Extract(savedCtx, carrier)

		spanName := r.Method + " " + r.URL.Path
		spanCtx, span := tracer.Start(parentCtx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.target", r.URL.Path),
				attribute.String("http.url", r.URL.String()),
			),
		)
		defer span.End()

		// Replace the request context so downstream handlers see the span.
		*r = *r.WithContext(spanCtx)

		ctx.Next()

		status := responseStatus(ctx)
		span.SetAttributes(attribute.Int("http.status_code", status))
	}
}

// responseStatus extracts the HTTP status code from the response writer. It
// relies on gin.ResponseWriter's Status() method via interface assertion.
func responseStatus(ctx httputil.Context) int {
	type statusProvider interface {
		Status() int
	}

	if rw, ok := ctx.Writer().(statusProvider); ok {
		return rw.Status()
	}

	return 200
}
