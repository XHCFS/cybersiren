package kafka

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	metricsOnce sync.Once

	consumedTotal *prometheus.CounterVec
	producedTotal *prometheus.CounterVec
	processingSec *prometheus.HistogramVec
)

// RegisterMetrics registers the pipeline-wide Kafka metrics on the given
// registry. Calling it more than once is a no-op (Prometheus would panic on
// duplicate registration).
func RegisterMetrics(reg *prometheus.Registry) {
	metricsOnce.Do(func() {
		consumedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cybersiren",
			Subsystem: "kafka",
			Name:      "messages_consumed_total",
			Help:      "Number of Kafka records successfully consumed.",
		}, []string{"service", "topic"})

		producedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cybersiren",
			Subsystem: "kafka",
			Name:      "messages_produced_total",
			Help:      "Number of Kafka records successfully produced.",
		}, []string{"service", "topic"})

		processingSec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "cybersiren",
			Subsystem: "pipeline",
			Name:      "processing_seconds",
			Help:      "Wall-clock time spent processing one Kafka record.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"service", "topic"})

		if reg != nil {
			reg.MustRegister(consumedTotal, producedTotal, processingSec)
		}
	})
}

// The accessors below are nil-safe so unit tests don't need to register.

// IncConsumed increments the consumed-records counter.
func IncConsumed(service, topic string) {
	if consumedTotal != nil {
		consumedTotal.WithLabelValues(service, topic).Inc()
	}
}

// IncProduced increments the produced-records counter.
func IncProduced(service, topic string) {
	if producedTotal != nil {
		producedTotal.WithLabelValues(service, topic).Inc()
	}
}

// ObserveProcessing records the per-record processing wall-clock time.
func ObserveProcessing(service, topic string, seconds float64) {
	if processingSec != nil {
		processingSec.WithLabelValues(service, topic).Observe(seconds)
	}
}
