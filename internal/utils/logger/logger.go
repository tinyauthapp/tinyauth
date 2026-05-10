package logger

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

type Logger struct {
	HTTP   zerolog.Logger
	App    zerolog.Logger
	config model.LogConfig
	base   zerolog.Logger
	audit  zerolog.Logger
	writer io.Writer
}

func NewLogger() *Logger {
	return &Logger{
		writer: os.Stderr,
		config: model.LogConfig{
			Level: "error",
			Json:  true,
			Streams: model.LogStreams{
				HTTP: model.LogStreamConfig{
					Enabled: true,
				},
				App: model.LogStreamConfig{
					Enabled: true,
				},
				// No reason to enable audit by default since it will be suppressed by the log level
			},
		},
	}
}

func (l *Logger) WithConfig(cfg model.LogConfig) *Logger {
	l.config = cfg
	return l
}

func (l *Logger) WithSimpleConfig() *Logger {
	l.config = model.LogConfig{
		Level: "info",
		Json:  false,
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: true},
			App:   model.LogStreamConfig{Enabled: true},
			Audit: model.LogStreamConfig{Enabled: false},
		},
	}
	return l
}

func (l *Logger) WithTestConfig() *Logger {
	l.config = model.LogConfig{
		Level: "trace",
		Streams: model.LogStreams{
			HTTP:  model.LogStreamConfig{Enabled: true},
			App:   model.LogStreamConfig{Enabled: true},
			Audit: model.LogStreamConfig{Enabled: true},
		},
	}
	return l
}

func (l *Logger) WithWriter(writer io.Writer) *Logger {
	l.writer = writer
	return l
}

func (l *Logger) Init() {
	base := log.With().
		Timestamp().
		Logger().
		Level(l.parseLogLevel(l.config.Level)).Output(l.writer)

	if !l.config.Json {
		base = base.Output(zerolog.ConsoleWriter{
			Out:        l.writer,
			TimeFormat: time.RFC3339,
		})
	}

	if base.GetLevel() == zerolog.TraceLevel || base.GetLevel() == zerolog.DebugLevel {
		base = base.With().Caller().Logger()
	}

	l.base = base
	l.audit = l.createLogger("audit", l.config.Streams.Audit)
	l.HTTP = l.createLogger("http", l.config.Streams.HTTP)
	l.App = l.createLogger("app", l.config.Streams.App)
}

func (l *Logger) parseLogLevel(level string) zerolog.Level {
	if level == "" {
		return zerolog.InfoLevel
	}
	parsed, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		log.Warn().Err(err).Str("level", level).Msg("Invalid log level, defaulting to error")
		parsed = zerolog.ErrorLevel
	}
	return parsed
}

func (l *Logger) createLogger(component string, cfg model.LogStreamConfig) zerolog.Logger {
	if !cfg.Enabled {
		return zerolog.Nop()
	}
	sub := l.base.With().Str("stream", component).Logger()
	if cfg.Level != "" {
		sub = sub.Level(l.parseLogLevel(cfg.Level))
	}
	return sub
}

func (l *Logger) AuditLoginSuccess(username, provider, ip string) {
	l.audit.Info().
		CallerSkipFrame(1).
		Str("event", "login").
		Str("result", "success").
		Str("username", username).
		Str("provider", provider).
		Str("ip", ip).
		Send()
}

func (l *Logger) AuditLoginFailure(username, provider, ip, reason string) {
	l.audit.Warn().
		CallerSkipFrame(1).
		Str("event", "login").
		Str("result", "failure").
		Str("username", username).
		Str("provider", provider).
		Str("ip", ip).
		Str("reason", reason).
		Send()
}

func (l *Logger) AuditLogout(username, provider, ip string) {
	l.audit.Info().
		CallerSkipFrame(1).
		Str("event", "logout").
		Str("result", "success").
		Str("username", username).
		Str("provider", provider).
		Str("ip", ip).
		Send()
}

// Used for testing
func (l *Logger) GetConfig() model.LogConfig {
	return l.config
}
