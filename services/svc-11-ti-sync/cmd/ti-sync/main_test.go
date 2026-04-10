package main

import (
	"bytes"
	"testing"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/config"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestWarnFeedConfiguration_WarnsForMissingMalwareBazaarKey(t *testing.T) {
	var logOutput bytes.Buffer
	logger := zerolog.New(&logOutput)

	warnFeedConfiguration(logger, &config.Config{}, []db.Feed{
		{Name: "malwarebazaar"},
	})

	assert.Contains(t, logOutput.String(), "malwarebazaar is enabled in db but no API key is configured")
}
