// Package topics offers a tiny admin helper used by /healthz endpoints to
// confirm broker reachability. Topic provisioning itself is done by the
// kafka-init.sh container, not from Go code.
package topics

import (
	"context"
	"fmt"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Ping connects to the broker and lists topics. Returns an error if the
// broker is unreachable or the call fails.
func Ping(ctx context.Context, brokers []string, clientID string) error {
	cli, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ClientID(clientID),
	)
	if err != nil {
		return fmt.Errorf("kafka admin client: %w", err)
	}
	defer cli.Close()

	adm := kadm.NewClient(cli)
	if _, err := adm.ListTopics(ctx); err != nil {
		return fmt.Errorf("list topics: %w", err)
	}
	return nil
}
