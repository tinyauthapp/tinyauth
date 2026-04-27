package tlog_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	"github.com/rs/zerolog"
	"gotest.tools/v3/assert"
)

func TestNewLogger(t *testing.T) {
	cfg := config.LogConfig{
		Level: "debug",
		Json:  true,
		Streams: config.LogStreams{
			HTTP:  config.LogStreamConfig{Enabled: true, Level: "info"},
			App:   config.LogStreamConfig{Enabled: true, Level: ""},
			Audit: config.LogStreamConfig{Enabled: false, Level: ""},
		},
	}

	logger := tlog.NewLogger(cfg)

	assert.Assert(t, logger != nil)
	assert.Assert(t, logger.HTTP.GetLevel() == zerolog.InfoLevel)
	assert.Assert(t, logger.App.GetLevel() == zerolog.DebugLevel)
	assert.Assert(t, logger.Audit.GetLevel() == zerolog.Disabled)
}

func TestNewSimpleLogger(t *testing.T) {
	logger := tlog.NewSimpleLogger()
	assert.Assert(t, logger != nil)
	assert.Assert(t, logger.HTTP.GetLevel() == zerolog.InfoLevel)
	assert.Assert(t, logger.App.GetLevel() == zerolog.InfoLevel)
	assert.Assert(t, logger.Audit.GetLevel() == zerolog.Disabled)
}

func TestLoggerInit(t *testing.T) {
	logger := tlog.NewSimpleLogger()
	logger.Init()

	assert.Assert(t, tlog.App.GetLevel() != zerolog.Disabled)
}

func TestLoggerWithDisabledStreams(t *testing.T) {
	cfg := config.LogConfig{
		Level: "info",
		Json:  false,
		Streams: config.LogStreams{
			HTTP:  config.LogStreamConfig{Enabled: false},
			App:   config.LogStreamConfig{Enabled: false},
			Audit: config.LogStreamConfig{Enabled: false},
		},
	}

	logger := tlog.NewLogger(cfg)

	assert.Assert(t, logger.HTTP.GetLevel() == zerolog.Disabled)
	assert.Assert(t, logger.App.GetLevel() == zerolog.Disabled)
	assert.Assert(t, logger.Audit.GetLevel() == zerolog.Disabled)
}

func TestLogStreamField(t *testing.T) {
	var buf bytes.Buffer

	cfg := config.LogConfig{
		Level: "info",
		Json:  true,
		Streams: config.LogStreams{
			HTTP:  config.LogStreamConfig{Enabled: true},
			App:   config.LogStreamConfig{Enabled: true},
			Audit: config.LogStreamConfig{Enabled: true},
		},
	}

	logger := tlog.NewLogger(cfg)

	// Override output for HTTP logger to capture output
	logger.HTTP = logger.HTTP.Output(&buf)

	logger.HTTP.Info().Msg("test message")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	assert.NilError(t, err)

	assert.Equal(t, "http", logEntry["log_stream"])
	assert.Equal(t, "test message", logEntry["message"])
}
