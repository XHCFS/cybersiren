// Package kafka is a thin wrapper over github.com/twmb/franz-go that the
// CyberSiren pipeline services use to talk to Redpanda. The producer and
// consumer subpackages provide the higher-level Publish/Run helpers used by
// pipeline stubs; this package owns the shared Prometheus metrics.
package kafka
