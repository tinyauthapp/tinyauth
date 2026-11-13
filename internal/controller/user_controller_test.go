package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestUserController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	totpCtx := &model.UserContext{
		Authenticated: false,
		Provider:      model.ProviderLocal,
		Local: &model.LocalContext{
			BaseContext: model.BaseContext{
				Username: "totpuser",
				Name:     "Totpuser",
				Email:    "totpuser@example.com",
			},
			TOTPPending: true,
		},
	}

	totpAttrCtx := &model.UserContext{
		Authenticated: false,
		Provider:      model.ProviderLocal,
		Local: &model.LocalContext{
			BaseContext: model.BaseContext{
				Username: "attrtotpuser",
				Name:     "Bob Jones",
				Email:    "bob@example.com",
			},
			TOTPPending: true,
		},
	}

	simpleCtx := &model.UserContext{
		Authenticated: true,
		Provider:      model.ProviderLocal,
		Local: &model.LocalContext{
			BaseContext: model.BaseContext{
				Username: "testuser",
				Name:     "Test User",
				Email:    "testuser@example.com",
			},
		},
	}

	nonExistentCtx := &model.UserContext{
		Authenticated: true,
		Provider:      model.ProviderLocal,
		Local: &model.LocalContext{
			BaseContext: model.BaseContext{
				Username: "idontexist",
				Name:     "I don't exist",
				Email:    "idontexist@example.com",
			},
		},
	}

	tdb, err := test.NewTestDatabase()
	require.NoError(t, err)
	store := tdb.Store()

	type runArgs struct {
		t            *testing.T
		router       *gin.Engine
		identitySvc  *service.IdentityService
		sessionsSvc  *service.SessionsService
		identityUUID *string
		sessionUUID  *string
	}

	type testCase struct {
		description string
		ctx         *model.UserContext
		run         func(args runArgs)
	}

	tests := []testCase{
		{
			description: "Login should fail gracefully on invalid json",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(`{"username": "testuser", "password":`))
				req.Header.Set("Content-Type", "application/json")

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 400, recorder.Code)
				assert.Contains(args.t, recorder.Body.String(), "Bad Request")
			},
		},
		{
			description: "Should fail on missing user",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()

				loginReq := LoginRequest{
					Username: "nonexistentuser",
					Password: "password",
				}

				loginReqBody, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 401, recorder.Code)
				assert.Len(args.t, recorder.Result().Cookies(), 0)
				assert.Contains(args.t, recorder.Body.String(), "Unauthorized")
			},
		},
		{
			description: "Should be able to login with valid credentials",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()

				loginReq := LoginRequest{
					Username: "testuser",
					Password: "password",
				}

				loginReqBody, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 200, recorder.Code)
				require.Len(args.t, recorder.Result().Cookies(), 1)

				cookie := recorder.Result().Cookies()[0]

				assert.Equal(args.t, "tinyauth-session", cookie.Name)
				assert.True(args.t, cookie.HttpOnly)
				assert.Equal(args.t, "example.com", cookie.Domain)

				// 3 seconds should be more than enough for even slow test environments
				assert.GreaterOrEqual(args.t, cookie.MaxAge, 7)
				assert.LessOrEqual(args.t, cookie.MaxAge, 10)
			},
		},
		{
			description: "Should reject login with invalid credentials",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()

				loginReq := LoginRequest{
					Username: "testuser",
					Password: "wrongpassword",
				}

				loginReqBody, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 401, recorder.Code)
				assert.Len(args.t, recorder.Result().Cookies(), 0)
				assert.Contains(args.t, recorder.Body.String(), "Unauthorized")
			},
		},
		{
			description: "Should rate limit on 3 invalid attempts",
			run: func(args runArgs) {
				loginReq := LoginRequest{
					Username: "testuser",
					Password: "wrongpassword",
				}

				loginReqBody, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				for range 3 {
					recorder := httptest.NewRecorder()

					req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
					req.Header.Set("Content-Type", "application/json")

					args.router.ServeHTTP(recorder, req)

					assert.Equal(args.t, 401, recorder.Code)
					assert.Len(args.t, recorder.Result().Cookies(), 0)
					assert.Contains(args.t, recorder.Body.String(), "Unauthorized")
				}

				// 4th attempt should be rate limited
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 429, recorder.Code)
				assert.Contains(args.t, recorder.Body.String(), "Too many failed login attempts.")
			},
		},
		{
			description: "Should not allow full login with TOTP",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()

				loginReq := LoginRequest{
					Username: "totpuser",
					Password: "password",
				}

				loginReqBody, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 200, recorder.Code)

				decodedBody := make(map[string]any)
				err = json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(args.t, err)

				assert.Equal(args.t, true, decodedBody["totpPending"])

				// should set the session cookie
				require.Len(args.t, recorder.Result().Cookies(), 1)
				cookie := recorder.Result().Cookies()[0]
				assert.Equal(args.t, "tinyauth-session", cookie.Name)
				assert.True(args.t, cookie.HttpOnly)
				assert.Equal(args.t, "example.com", cookie.Domain)
				assert.GreaterOrEqual(args.t, cookie.MaxAge, 3597)
				assert.LessOrEqual(args.t, cookie.MaxAge, 3600)
			},
		},
		{
			description: "Should be able to logout",
			ctx:         simpleCtx,
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/logout", nil)
				req.AddCookie(&http.Cookie{
					Name:  "tinyauth-session",
					Value: *args.sessionUUID,
				})

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(args.t, cookies, 1)

				cookie := cookies[0]
				assert.Equal(args.t, "tinyauth-session", cookie.Name)
				assert.Equal(args.t, "", cookie.Value)
				assert.Equal(args.t, -1, cookie.MaxAge) // MaxAge -1 means delete cookie
			},
		},
		{
			description: "Logout should be treated as valid without a session cookie",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/logout", nil)
				args.router.ServeHTTP(recorder, req)
				assert.Equal(args.t, 200, recorder.Code)
			},
		},
		{
			description: "TOTP should gracefully reject invalid json",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(`{"code":`))
				req.Header.Set("Content-Type", "application/json")
				args.router.ServeHTTP(recorder, req)
				assert.Equal(args.t, 400, recorder.Code)
				assert.Contains(args.t, recorder.Body.String(), "Bad Request")
			},
		},
		{
			description: "TOTP should fail on non-totp context",
			ctx:         simpleCtx,
			run: func(args runArgs) {
				totpReq := TotpRequest{
					Code: "123456",
				}

				totpReqBody, err := json.Marshal(totpReq)
				require.NoError(args.t, err)

				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
				req.Header.Set("Content-Type", "application/json")
				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 401, recorder.Code)
				assert.Contains(args.t, recorder.Body.String(), "Unauthorized")
			},
		},
		{
			description: "TOTP should fail when user in context doesn't exist",
			ctx:         nonExistentCtx,
			run: func(args runArgs) {
				totpReq := TotpRequest{
					Code: "123456",
				}

				totpReqBody, err := json.Marshal(totpReq)
				require.NoError(args.t, err)

				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
				req.Header.Set("Content-Type", "application/json")
				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 401, recorder.Code)
				assert.Contains(args.t, recorder.Body.String(), "Unauthorized")
			},
		},
		{
			description: "Should be able to login with TOTP",
			ctx:         totpCtx,
			run: func(args runArgs) {
				code, err := totp.GenerateCode("JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK", time.Now())
				require.NoError(args.t, err)

				totpReq := TotpRequest{
					Code: code,
				}

				totpReqBody, err := json.Marshal(totpReq)
				require.NoError(args.t, err)

				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(&http.Cookie{
					Name:  "tinyauth-session",
					Value: *args.sessionUUID,
				})

				args.router.ServeHTTP(recorder, req)

				require.Equal(args.t, 200, recorder.Code)
				require.Len(args.t, recorder.Result().Cookies(), 1)

				// should set a new session cookie with totp pending removed
				totpCookie := recorder.Result().Cookies()[0]
				assert.Equal(args.t, "tinyauth-session", totpCookie.Name)
				assert.True(args.t, totpCookie.HttpOnly)
				assert.Equal(args.t, "example.com", totpCookie.Domain)
				assert.GreaterOrEqual(args.t, totpCookie.MaxAge, 7)
				assert.LessOrEqual(args.t, totpCookie.MaxAge, 10)

				completed, err := args.sessionsSvc.Get(context.TODO(), totpCookie.Value)
				require.NoError(args.t, err)
				assert.Equal(args.t, *args.identityUUID, completed.Session.IdentityUUID)
				assert.False(args.t, completed.SessionContext.Local.TOTPPending)
			},
		},
		{
			description: "TOTP should rate limit on multiple invalid attempts",
			ctx:         totpCtx,
			run: func(args runArgs) {
				for range 3 {
					totpReq := TotpRequest{
						Code: "000000", // invalid code, hopefully
					}

					totpReqBody, err := json.Marshal(totpReq)
					require.NoError(args.t, err)

					recorder := httptest.NewRecorder()
					req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
					req.Header.Set("Content-Type", "application/json")
					req.AddCookie(&http.Cookie{
						Name:  "tinyauth-session",
						Value: *args.sessionUUID,
					})

					args.router.ServeHTTP(recorder, req)

					assert.Equal(args.t, 401, recorder.Code)
					assert.Contains(args.t, recorder.Body.String(), "Unauthorized")
				}

				// 4th attempt should be rate limited
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(`{"code":"000000"}`)))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(&http.Cookie{
					Name:  "tinyauth-session",
					Value: *args.sessionUUID,
				})

				args.router.ServeHTTP(recorder, req)

				assert.Equal(args.t, 429, recorder.Code)
				assert.Contains(args.t, recorder.Body.String(), "Too many failed TOTP attempts.")
			},
		},
		{
			description: "Login uses name and email from user attributes",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()
				loginReq := LoginRequest{Username: "attruser", Password: "password"}
				body, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				args.router.ServeHTTP(recorder, req)

				require.Equal(args.t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(args.t, cookies, 1)
				assert.Equal(args.t, "tinyauth-session", cookies[0].Name)
			},
		},
		{
			description: "Login with TOTP uses name and email from user attributes in pending session",
			run: func(args runArgs) {
				recorder := httptest.NewRecorder()
				loginReq := LoginRequest{Username: "attrtotpuser", Password: "password"}
				body, err := json.Marshal(loginReq)
				require.NoError(args.t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				args.router.ServeHTTP(recorder, req)

				require.Equal(args.t, 200, recorder.Code)
				var res map[string]any
				require.NoError(args.t, json.Unmarshal(recorder.Body.Bytes(), &res))
				assert.Equal(args.t, true, res["totpPending"])
				require.Len(args.t, recorder.Result().Cookies(), 1)
			},
		},
		{
			description: "TOTP completion uses name and email from user attributes",
			ctx:         totpAttrCtx,
			run: func(args runArgs) {
				code, err := totp.GenerateCode("JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK", time.Now())
				require.NoError(args.t, err)

				totpReq := TotpRequest{Code: code}
				body, err := json.Marshal(totpReq)
				require.NoError(args.t, err)

				recorder := httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(&http.Cookie{
					Name:  "tinyauth-session",
					Value: *args.sessionUUID,
				})
				args.router.ServeHTTP(recorder, req)

				require.Equal(args.t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(args.t, cookies, 1)
				assert.Equal(args.t, "tinyauth-session", cookies[0].Name)
			},
		},
	}

	ctx := context.TODO()
	dg := ding.New(ctx)

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

	identityService, err := service.NewIdentityService(service.IdentityServiceInput{
		Store:   store,
		Config:  &cfg,
		Runtime: &runtime,
	})
	require.NoError(t, err)

	sessionsService := service.NewSessionsService(service.SessionsServiceInput{
		Store:    store,
		Identity: identityService,
		Config:   &cfg,
		Runtime:  &runtime,
	})

	beforeEach := func() {
		// Clear failed login attempts before each test
		authService.ClearLoginAttempts()
	}

	for _, tc := range tests {
		beforeEach()
		t.Run(tc.description, func(tct *testing.T) {
			router := gin.Default()

			args := runArgs{
				t:           tct,
				router:      router,
				identitySvc: identityService,
				sessionsSvc: sessionsService,
			}

			if tc.ctx != nil {
				ident, err := identityService.Store(context.TODO(), service.StoreIdentityParams{
					Username:       tc.ctx.GetUsername(),
					Email:          tc.ctx.GetEmail(),
					Name:           tc.ctx.GetName(),
					ProviderID:     "local",
					ProviderType:   model.ProviderLocal,
					ProviderUserID: "local:" + tc.ctx.GetUsername(),
				})
				require.NoError(tct, err)

				sess, err := sessionsService.Create(context.TODO(), ident.UUID, model.SessionContext{
					Local: model.SessionLocalContext{
						TOTPPending: tc.ctx.TOTPPending(),
					},
				})
				require.NoError(tct, err)

				args.sessionUUID = &sess.UUID
				args.identityUUID = &ident.UUID

				router.Use(func(ctx *gin.Context) {
					ctx.Set("context", tc.ctx)
					ctx.Next()
				})
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			NewUserController(UserControllerInput{
				Log:           log,
				RuntimeConfig: &runtime,
				RouterGroup:   group,
				AuthService:   authService,
				Identity:      identityService,
				Sessions:      sessionsService,
			})

			tc.run(args)
		})
	}
}
