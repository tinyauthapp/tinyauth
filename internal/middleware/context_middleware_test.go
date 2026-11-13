package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"golang.org/x/crypto/bcrypt"
)

func TestContextMiddleware(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	colonPasswd, err := bcrypt.GenerateFromPassword([]byte("pa:ss"), bcrypt.DefaultCost)
	require.NoError(t, err)
	runtime.LocalUsers = append(runtime.LocalUsers, model.LocalUser{
		Username: "colonuser",
		Password: string(colonPasswd),
	})

	type runArgs struct {
		do          func(req *http.Request) (*model.UserContext, *httptest.ResponseRecorder)
		queries     repository.Store
		cfg         *model.Config
		identitySvc *service.IdentityService
		sessionsSvc *service.SessionsService
	}

	seedSession := func(t *testing.T, args runArgs, ctx model.UserContext) string {
		t.Helper()
		ident, err := args.identitySvc.Store(context.TODO(), service.StoreIdentityParams{
			Username:       ctx.GetUsername(),
			Email:          ctx.GetEmail(),
			Name:           ctx.GetName(),
			ProviderID:     "local",
			ProviderType:   model.ProviderLocal,
			ProviderUserID: "local:" + ctx.GetUsername(),
		})
		require.NoError(t, err)

		sess, err := args.sessionsSvc.Create(context.TODO(), ident.UUID, model.SessionContext{
			Local: model.SessionLocalContext{
				TOTPPending: ctx.TOTPPending(),
			},
		})
		require.NoError(t, err)

		return sess.UUID
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
				req.Header.Set("Authorization", utils.EncodeBasicAuth("testuser", "password"))
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
				uuid := seedSession(t, args, model.UserContext{
					Authenticated: true,
					Provider:      model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{
							Username: "testuser",
						},
					},
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
			description: "Session cookie with TOTP pending sets unauthenticated context with TOTP enabled",
			run: func(t *testing.T, args runArgs) {
				uuid := seedSession(t, args, model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{
							Username: "totpuser",
						},
						TOTPPending: true,
					},
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
				uuid := seedSession(t, args, model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{
							Username: "ghostuser",
						},
					},
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
				// modify the expiry to 1 second (it's a pointer, so the session service will use it)
				args.cfg.Auth.SessionExpiry = 1
				uuid := seedSession(t, args, model.UserContext{
					Authenticated: true,
					Provider:      model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{
							Username: "testuser",
						},
					},
				})

				// reset it back to 10 seconds
				args.cfg.Auth.SessionExpiry = 10

				// wait 2 seconds just to be sure it expired
				time.Sleep(2 * time.Second)

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
				req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("testuser", "password"))
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
				req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("testuser", "wrongpassword"))
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Basic auth is rejected for users with totp",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("totpuser", "password"))
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
		{
			description: "Locked account on basic auth sets lock headers",
			run: func(t *testing.T, args runArgs) {
				for range 3 {
					req := httptest.NewRequest("GET", "/api/test", nil)
					req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("testuser", "wrongpassword"))
					args.do(req)
				}

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("testuser", "password"))
				userCtx, recorder := args.do(req)

				assert.Nil(t, userCtx)
				assert.Equal(t, "true", recorder.Header().Get("x-tinyauth-lock-locked"))
				assert.NotEmpty(t, recorder.Header().Get("x-tinyauth-lock-reset"))
			},
		},
		{
			description: "Cookie auth takes precedence over basic auth",
			run: func(t *testing.T, args runArgs) {
				uuid := seedSession(t, args, model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{
							Username: "testuser",
						},
					},
				})

				req := httptest.NewRequest("GET", "/api/test", nil)
				req.AddCookie(&http.Cookie{Name: "tinyauth-session", Value: uuid})
				req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("totpuser", "password"))
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
				req.Header.Set("Authorization", "Basic "+utils.EncodeBasicAuth("testuser", "password"))
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
			},
		},
		{
			description: "Valid x-tinyauth-Authorization sets authenticated local context",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("x-tinyauth-authorization", "Basic "+utils.EncodeBasicAuth("testuser", "password"))
				req.SetBasicAuth("testuser", "password")
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, model.ProviderLocal, userCtx.Provider)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
			},
		},
		{
			description: "x-tinyauth-authorization takes priority over authorization",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("x-tinyauth-authorization", "Basic "+utils.EncodeBasicAuth("testuser", "password"))
				req.Header.Set("authorization", "Basic "+utils.EncodeBasicAuth("testuser", "wrongpassword"))
				userCtx, _ := args.do(req)

				require.NotNil(t, userCtx)
				assert.Equal(t, "testuser", userCtx.GetUsername())
				assert.True(t, userCtx.Authenticated)
			},
		},
		{
			description: "x-tinyauth-authorization header being invalid doesn't fail the request",
			run: func(t *testing.T, args runArgs) {
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.Header.Set("x-tinyauth-authorization", "Basic "+utils.EncodeBasicAuth("testuser", "wrongpassword"))
				userCtx, _ := args.do(req)

				assert.Nil(t, userCtx)
			},
		},
	}

	ctx := context.TODO()
	dg := ding.New(ctx)

	tdb, err := test.NewTestDatabase()
	require.NoError(t, err)
	store := tdb.Store()

	policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	require.NoError(t, err)

	broker := service.NewOAuthBrokerService(service.OAuthBrokerServiceInput{
		Log:     log,
		Runtime: &runtime,
		Ctx:     ctx,
		Ding:    dg,
	})

	authService, err := service.NewAuthService(service.AuthServiceInput{
		Log:          log,
		Config:       &cfg,
		Runtime:      &runtime,
		Ctx:          ctx,
		Ding:         dg,
		LDAP:         nil,
		Queries:      store,
		OAuthBroker:  broker,
		Tailscale:    nil,
		PolicyEngine: policyEngine,
	})
	require.NoError(t, err)

	identitySvc, err := service.NewIdentityService(service.IdentityServiceInput{
		Store:   store,
		Config:  &cfg,
		Runtime: &runtime,
	})
	require.NoError(t, err)

	sessionSvc := service.NewSessionsService(service.SessionsServiceInput{
		Store:    store,
		Identity: identitySvc,
		Config:   &cfg,
		Runtime:  &runtime,
	})

	contextMiddleware := NewContextMiddleware(ContextMiddlewareInput{
		Log:              log,
		RuntimeConfig:    &runtime,
		AuthService:      authService,
		BrokerService:    broker,
		TailscaleService: nil,
		Identity:         identitySvc,
		Session:          sessionSvc,
	})

	for _, tc := range tests {
		authService.ClearLoginAttempts()
		t.Run(tc.description, func(tct *testing.T) {
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

			tc.run(tct, runArgs{do: do, queries: store, sessionsSvc: sessionSvc, identitySvc: identitySvc, cfg: &cfg})
		})
	}
}
