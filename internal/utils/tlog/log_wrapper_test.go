package tlog_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	"github.com/rs/zerolog"
)

func TestNewLogger(t *testing.T) {
	cfg := model.LogConfig{
		Level: "debug",
		Json:  true,
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: true, Level: "info"},
			App:   model.LogStreamConfig{Enabled: true, Level: ""},
			Audit: model.LogStreamConfig{Enabled: false, Level: ""},
		},
	}

	logger := tlog.NewLogger(cfg)

	assert.NotNil(t, logger)
	assert.Equal(t, zerolog.InfoLevel, logger.HTTP.GetLevel())
	assert.Equal(t, zerolog.DebugLevel, logger.App.GetLevel())
	assert.Equal(t, zerolog.Disabled, logger.Audit.GetLevel())
}

func TestNewSimpleLogger(t *testing.T) {
	logger := tlog.NewSimpleLogger()
	assert.NotNil(t, logger)
	assert.Equal(t, zerolog.InfoLevel, logger.HTTP.GetLevel())
	assert.Equal(t, zerolog.InfoLevel, logger.App.GetLevel())
	assert.Equal(t, zerolog.Disabled, logger.Audit.GetLevel())
}

func TestLoggerInit(t *testing.T) {
	logger := tlog.NewSimpleLogger()
	logger.Init()

	assert.NotEqual(t, zerolog.Disabled, tlog.App.GetLevel())
}

func TestLoggerWithDisabledStreams(t *testing.T) {
	cfg := model.LogConfig{
		Level: "info",
		Json:  false,
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: false},
			App:   model.LogStreamConfig{Enabled: false},
			Audit: model.LogStreamConfig{Enabled: false},
		},
	}

	logger := tlog.NewLogger(cfg)

	assert.Equal(t, zerolog.Disabled, logger.HTTP.GetLevel())
	assert.Equal(t, zerolog.Disabled, logger.App.GetLevel())
	assert.Equal(t, zerolog.Disabled, logger.Audit.GetLevel())
}

func TestLogStreamField(t *testing.T) {
	var buf bytes.Buffer

	cfg := model.LogConfig{
		Level: "info",
		Json:  true,
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: true},
			App:   model.LogStreamConfig{Enabled: true},
			Audit: model.LogStreamConfig{Enabled: true},
		},
	}

	logger := tlog.NewLogger(cfg)

	// Override output for HTTP logger to capture output
	logger.HTTP = logger.HTTP.Output(&buf)

	logger.HTTP.Info().Msg("test message")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	assert.NoError(t, err)

	assert.Equal(t, "http", logEntry["log_stream"])
	assert.Equal(t, "test message", logEntry["message"])
}
