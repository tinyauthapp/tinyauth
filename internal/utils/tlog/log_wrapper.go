package tlog

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

type Logger struct {
	Audit zerolog.Logger
	HTTP  zerolog.Logger
	App   zerolog.Logger
}

var (
	Audit zerolog.Logger
	HTTP  zerolog.Logger
	App   zerolog.Logger
)

func NewLogger(cfg model.LogConfig) *Logger {
	baseLogger := log.With().
		Timestamp().
		Caller().
		Logger().
		Level(parseLogLevel(cfg.Level))

	if !cfg.Json {
		baseLogger = baseLogger.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	}

	return &Logger{
		Audit: createLogger("audit", cfg.Streams.Audit, baseLogger),
		HTTP:  createLogger("http", cfg.Streams.HTTP, baseLogger),
		App:   createLogger("app", cfg.Streams.App, baseLogger),
	}
}

func NewSimpleLogger() *Logger {
	return NewLogger(model.LogConfig{
		Level: "info",
		Json:  false,
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: true},
			App:   model.LogStreamConfig{Enabled: true},
			Audit: model.LogStreamConfig{Enabled: false},
		},
	})
}

func NewTestLogger() *Logger {
	return NewLogger(model.LogConfig{
		Level: "trace",
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: true},
			App:   model.LogStreamConfig{Enabled: true},
			Audit: model.LogStreamConfig{Enabled: true},
		},
	})
}

func (l *Logger) Init() {
	Audit = l.Audit
	HTTP = l.HTTP
	App = l.App
}

func createLogger(component string, streamCfg model.LogStreamConfig, baseLogger zerolog.Logger) zerolog.Logger {
	if !streamCfg.Enabled {
		return zerolog.Nop()
	}
	subLogger := baseLogger.With().Str("log_stream", component).Logger()
	// override level if specified, otherwise use base level
	if streamCfg.Level != "" {
		subLogger = subLogger.Level(parseLogLevel(streamCfg.Level))
	}
	return subLogger
}

func parseLogLevel(level string) zerolog.Level {
	if level == "" {
		return zerolog.InfoLevel
	}
	parsedLevel, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		log.Warn().Err(err).Str("level", level).Msg("Invalid log level, defaulting to info")
		parsedLevel = zerolog.InfoLevel
	}
	return parsedLevel
}
