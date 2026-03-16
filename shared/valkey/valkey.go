package valkey

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeyotel"

	"github.com/saif/cybersiren/shared/observability/tracing"
)

// ClientOptions holds configurable valkey/redis connection parameters.
// Zero values mean "no auth" and "default DB (0)".
type ClientOptions struct {
	Addr     string
	Password string
	DB       int
}

func New(opts ClientOptions, log zerolog.Logger) (valkeygo.Client, error) {
	trimmedAddr := strings.TrimSpace(opts.Addr)
	if trimmedAddr == "" {
		return nil, fmt.Errorf("valkey addr is empty")
	}

	opt := valkeygo.ClientOption{
		InitAddress:      []string{trimmedAddr},
		ConnWriteTimeout: 3 * time.Second,
		SelectDB:         opts.DB,
		Password:         opts.Password,
	}
	opt.Dialer = net.Dialer{Timeout: 5 * time.Second}

	_ = tracing.Tracer("shared/valkey")

	client, err := valkeyotel.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("create valkey client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ping valkey: %w", err)
	}

	log.Info().
		Str("valkey_addr", trimmedAddr).
		Msg("connected to valkey")

	return client, nil
}

func MustNew(opts ClientOptions, log zerolog.Logger) valkeygo.Client {
	client, err := New(opts, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize valkey client")
		return nil
	}

	return client
}
