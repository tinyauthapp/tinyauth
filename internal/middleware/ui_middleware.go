package middleware

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/assets"

	"github.com/gin-gonic/gin"
)

type UIMiddleware struct {
	uiFs         fs.FS
	uiFileServer http.Handler
}

func NewUIMiddleware() (*UIMiddleware, error) {
	m := &UIMiddleware{}

	ui, err := fs.Sub(assets.FrontendAssets, "dist")

	if err != nil {
		return nil, fmt.Errorf("failed to load ui assets: %w", err)
	}

	m.uiFs = ui
	m.uiFileServer = http.FileServerFS(ui)

	return m, nil
}

func (m *UIMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/")

		switch strings.SplitN(path, "/", 2)[0] {
		case "api", "resources", ".well-known":
			c.Next()
			return
		case "robots.txt":
			c.Writer.Header().Set("Content-Type", "text/plain")
			c.Writer.WriteHeader(http.StatusOK)
			c.Writer.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		default:
			_, err := fs.Stat(m.uiFs, path)

			// Enough for one authentication flow
			maxAge := 15 * time.Minute

			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			} else if strings.HasPrefix(path, "assets/") {
				// assets are named with a hash and can be cached for a long time
				maxAge = 30 * 24 * time.Hour
			}

			c.Writer.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
			m.uiFileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
			return
		}
	}
}
