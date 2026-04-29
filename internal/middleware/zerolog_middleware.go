package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

// See context middleware for explanation of why we have to do this
var (
	loggerSkipPathsPrefix = []string{
		"GET /api/healthz",
		"HEAD /api/healthz",
		"GET /favicon.ico",
	}
)

type ZerologMiddleware struct{}

func NewZerologMiddleware() *ZerologMiddleware {
	return &ZerologMiddleware{}
}

func (m *ZerologMiddleware) Init() error {
	return nil
}

func (m *ZerologMiddleware) logPath(path string) bool {
	for _, prefix := range loggerSkipPathsPrefix {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func (m *ZerologMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tStart := time.Now()

		c.Next()

		code := c.Writer.Status()
		address := c.Request.RemoteAddr
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path

		latency := time.Since(tStart).String()

		subLogger := tlog.HTTP.With().Str("method", method).
			Str("path", path).
			Str("address", address).
			Str("client_ip", clientIP).
			Int("status", code).
			Str("latency", latency).Logger()

		if m.logPath(method + " " + path) {
			switch {
			case code >= 400 && code < 500:
				subLogger.Warn().Msg("Client Error")
			case code >= 500:
				subLogger.Error().Msg("Server Error")
			default:
				subLogger.Info().Msg("Request")
			}
		} else {
			subLogger.Debug().Msg("Request")
		}
	}
}
