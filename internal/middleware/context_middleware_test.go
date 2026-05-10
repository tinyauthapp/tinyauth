package middleware_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/middleware"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestContextMiddleware(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	basicAuthHeader := func(username, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	seedSession := func(t *testing.T, queries *repository.Queries, params repository.CreateSessionParams) {
		t.Helper()
		_, err := queries.CreateSession(context.Background(), params)
		require.NoError(t, err)
	}

	type runArgs struct {
		do      func(req *http.Request) (*model.UserContext, *httptest.ResponseRecorder)
		queries *repository.Queries
	}

	type testCase struct {
		description string
		run         func(t *testing.T, args runArgs)
	}

	tests := []testCase{
		{
			description: "Skip path bypasses auth processing",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/healthz", nil)
				req.Header.Set("Authorization", basicAuthHeader("testuser", "password"))
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "No credentials yields no context",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Valid session cookie sets authenticated local context",
			run: func(t *testing.T, args runArgs) {
				uuid := "session-valid-local"
				seedSession(t, args.queries, repository.CreateSessionParams{
					UUID:      uuid,
					Username:  "testuser",
					Provider:  "local",
					Expiry:    time.Now().Add(10 * time.Second).Unix(),
					CreatedAt: time.Now().Unix(),
				})

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: uuid})
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, model.ProviderLocal, userCtx.Provider)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
				require.NotNil(t, userCtx.Local)
			},
		},
		{
			description: "Session cookie with totp pending sets unauthenticated context with totp enabled",
			run: func(t *testing.T, args runArgs) {
				uuid := "session-totp-pending"
				seedSession(t, args.queries, repository.CreateSessionParams{
					UUID:        uuid,
					Username:    "totpuser",
					Provider:    "local",
					TotpPending: true,
					Expiry:      time.Now().Add(60 * time.Second).Unix(),
					CreatedAt:   time.Now().Unix(),
				})

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: uuid})
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, "totpuser", userCtx.GetUsername())
				assert.False(t, userCtx.Authenticated)
				require.NotNil(t, userCtx.Local)
				assert.True(t, userCtx.Local.TOTPPending)
			},
		},
		{
			description: "Unknown session cookie yields no context",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: "does-not-exist"})
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Session for missing local user yields no context",
			run: func(t *testing.T, args runArgs) {
				uuid := "session-deleted-user"
				seedSession(t, args.queries, repository.CreateSessionParams{
					UUID:      uuid,
					Username:  "ghostuser",
					Provider:  "local",
					Expiry:    time.Now().Add(10 * time.Second).Unix(),
					CreatedAt: time.Now().Unix(),
				})

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: uuid})
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Expired session cookie yields no context",
			run: func(t *testing.T, args runArgs) {
				uuid := "session-expired"
				seedSession(t, args.queries, repository.CreateSessionParams{
					UUID:      uuid,
					Username:  "testuser",
					Provider:  "local",
					Expiry:    time.Now().Add(-1 * time.Second).Unix(),
					CreatedAt: time.Now().Add(-10 * time.Second).Unix(),
				})

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: uuid})
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Valid basic auth sets authenticated local context",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", basicAuthHeader("testuser", "password"))
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, model.ProviderLocal, userCtx.Provider)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
			},
		},
		{
			description: "Invalid basic auth password yields no context",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", basicAuthHeader("testuser", "wrongpassword"))
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Basic auth is rejected for users with totp",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", basicAuthHeader("totpuser", "password"))
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Locked account on basic auth sets lock headers",
			run: func(t *testing.T, args runArgs) {
				for range 3 {
					req := httptest.NewRequest("GET", "/api/test", nil)
					req.Header.Set("Authorization", basicAuthHeader("testuser", "wrongpassword"))
					args.do(req)
				}

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", basicAuthHeader("testuser", "password"))
				userCtx, recorder := args.do(req)

				assert.Nil(t, userCtx)
				assert.Equal(t, "true", recorder.Header().Get("x-tinyauth-lock-locked"))
				assert.NotEmpty(t, recorder.Header().Get("x-tinyauth-lock-reset"))
			},
		},
		{
			description: "Cookie auth takes precedence over basic auth",
			run: func(t *testing.T, args runArgs) {
				uuid := "session-precedence"
				seedSession(t, args.queries, repository.CreateSessionParams{
					UUID:      uuid,
					Username:  "testuser",
					Provider:  "local",
					Expiry:    time.Now().Add(10 * time.Second).Unix(),
					CreatedAt: time.Now().Unix(),
				})

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: uuid})
				req.Header.Set("Authorization", basicAuthHeader("totpuser", "password"))
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
			},
		},
		{
			description: "Ensure fallback to basic auth when cookie is missing",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", basicAuthHeader("testuser", "password"))
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
			},
		},
	}

	ctx := context.TODO()
	wg := &sync.WaitGroup{}

	app := bootstrap.NewBootstrapApp(cfg)

	err := app.SetupDatabase()
	require.NoError(t, err)

	queries := repository.New(app.GetDB())

	broker := service.NewOAuthBrokerService(log, map[string]model.OAuthServiceConfig{}, ctx)
	authService := service.NewAuthService(log, cfg, runtime, ctx, wg, nil, queries, broker)

	contextMiddleware := middleware.NewContextMiddleware(log, runtime, authService, broker)

	for _, test := range tests {
		authService.ClearRateLimitsTestingOnly()
		t.Run(test.description, func(t *testing.T) {
			gin.SetMode(gin.TestMode)

			do := func(req *http.Request) (*model.UserContext, *httptest.ResponseRecorder) {
				var captured *model.UserContext
				router := gin.New()
				router.Use(contextMiddleware.Middleware())
				handler := func(c *gin.Context) {
					if val, exists := c.Get("context"); exists {
						captured, _ = val.(*model.UserContext)
					}
				}
				router.GET("/api/test", handler)
				router.GET("/api/healthz", handler)

				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, req)
				return captured, recorder
			}

			test.run(t, runArgs{do: do, queries: queries})
		})
	}

	t.Cleanup(func() {
		app.GetDB().Close()
	})
}
