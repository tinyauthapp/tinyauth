package logger_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestLogger(t *testing.T) {
	type testCase struct {
		description string
		run         func(t *testing.T)
	}

	tests := []testCase{
		{
			description: "Should create a simple logger with the expected config",
			run: func(t *testing.T) {
				l := logger.NewLogger().WithSimpleConfig()
				l.Init()

				cfg := l.GetConfig()

				assert.Equal(t, cfg, model.LogConfig{
					Level: "info",
					Json:  false,
					Streams: model.LogStreams{
						HTTP:  model.LogStreamConfig{Enabled: true},
						App:   model.LogStreamConfig{Enabled: true},
						Audit: model.LogStreamConfig{Enabled: false},
					},
				})
			},
		},
		{
			description: "Should create a test logger with the expected config",
			run: func(t *testing.T) {
				l := logger.NewLogger().WithTestConfig()
				l.Init()

				cfg := l.GetConfig()

				assert.Equal(t, cfg, model.LogConfig{
					Level: "trace",
					Json:  false,
					Streams: model.LogStreams{
						HTTP:  model.LogStreamConfig{Enabled: true},
						App:   model.LogStreamConfig{Enabled: true},
						Audit: model.LogStreamConfig{Enabled: true},
					},
				})
			},
		},
		{
			description: "Should create a logger with a custom config",
			run: func(t *testing.T) {
				customCfg := model.LogConfig{
					Level: "debug",
					Json:  true,
					Streams: model.LogStreams{
						HTTP:  model.LogStreamConfig{Enabled: false},
						App:   model.LogStreamConfig{Enabled: true},
						Audit: model.LogStreamConfig{Enabled: false},
					},
				}

				l := logger.NewLogger().WithConfig(customCfg)
				l.Init()

				cfg := l.GetConfig()

				assert.Equal(t, cfg, customCfg)
			},
		},
		{
			description: "Default logger should use error type and log json",
			run: func(t *testing.T) {
				buf := bytes.Buffer{}

				l := logger.NewLogger().WithWriter(&buf)
				l.Init()

				cfg := l.GetConfig()

				assert.Equal(t, cfg, model.LogConfig{
					Level: "error",
					Json:  true,
					Streams: model.LogStreams{
						HTTP:  model.LogStreamConfig{Enabled: true},
						App:   model.LogStreamConfig{Enabled: true},
						Audit: model.LogStreamConfig{Enabled: false},
					},
				})

				l.App.Error().Msg("test")

				var entry map[string]any
				err := json.Unmarshal(buf.Bytes(), &entry)
				require.NoError(t, err)

				assert.Equal(t, "test", entry["message"])
				assert.Equal(t, "app", entry["stream"])
				assert.Equal(t, "error", entry["level"])
				assert.NotEmpty(t, entry["time"])
			},
		},
		{
			description: "Should default to error level if an invalid level is provided",
			run: func(t *testing.T) {
				buf := bytes.Buffer{}

				customCfg := model.LogConfig{
					Level: "invalid",
					Json:  false,
					Streams: model.LogStreams{
						HTTP:  model.LogStreamConfig{Enabled: true},
						App:   model.LogStreamConfig{Enabled: true},
						Audit: model.LogStreamConfig{Enabled: false},
					},
				}

				l := logger.NewLogger().WithConfig(customCfg).WithWriter(&buf)
				l.Init()

				assert.Equal(t, zerolog.ErrorLevel, l.App.GetLevel())
				assert.Equal(t, zerolog.ErrorLevel, l.HTTP.GetLevel())

				// should not get logged
				l.AuditLoginFailure("test", "test", "test", "test")

				assert.Empty(t, buf.String())
			},
		},
		{
			description: "Should use nop logger for disabled streams",
			run: func(t *testing.T) {
				buf := bytes.Buffer{}

				customCfg := model.LogConfig{
					Level: "info",
					Json:  false,
					Streams: model.LogStreams{
						HTTP:  model.LogStreamConfig{Enabled: false},
						App:   model.LogStreamConfig{Enabled: true},
						Audit: model.LogStreamConfig{Enabled: false},
					},
				}

				l := logger.NewLogger().WithConfig(customCfg).WithWriter(&buf)
				l.Init()

				assert.Equal(t, zerolog.Disabled, l.HTTP.GetLevel())

				l.App.Info().Msg("test")

				l.AuditLoginFailure("test_nop", "test_nop", "test_nop", "test_nop")

				assert.NotEmpty(t, buf.String())
				assert.NotContains(t, buf.String(), "test_nop")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, test.run)
	}
}
