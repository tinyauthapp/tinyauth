package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/service"
	testutil "github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestOIDCEndSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		description       string
		method            string
		configureRequest  func(values url.Values, idToken string)
		provider          *model.OAuthServiceConfig
		expectedStatus    int
		expectedRedirect  string
		expectedCallback  string
		expectSessionGone bool
		validateRedirect  func(t *testing.T, location string)
	}{
		{
			description: "GET cascades a valid end-session request to the upstream provider",
			method:      http.MethodGet,
			configureRequest: func(values url.Values, idToken string) {
				values.Set("id_token_hint", idToken)
				values.Set("client_id", "some-client-id")
				values.Set("post_logout_redirect_uri", "https://rp.example.net/logged-out")
				values.Set("state", "state-123")
			},
			provider: &model.OAuthServiceConfig{
				ClientID:  "upstream-client",
				LogoutURL: "https://id.example.com/api/oidc/end-session",
			},
			expectedStatus:    http.StatusFound,
			expectedCallback:  "https://rp.example.net/logged-out?state=state-123",
			expectSessionGone: true,
			validateRedirect: func(t *testing.T, location string) {
				parsed, err := url.Parse(location)
				require.NoError(t, err)
				assert.Equal(t, "id.example.com", parsed.Host)
				assert.Equal(t, "upstream-id-token", parsed.Query().Get("id_token_hint"))
				assert.Equal(t, "upstream-client", parsed.Query().Get("client_id"))
				assert.NotEmpty(t, parsed.Query().Get("state"))
				assert.NotContains(t, parsed.Query().Get("state"), "rp.example.net")
			},
		},
		{
			description: "POST redirects directly to a registered post-logout URI",
			method:      http.MethodPost,
			configureRequest: func(values url.Values, idToken string) {
				values.Set("id_token_hint", idToken)
				values.Set("post_logout_redirect_uri", "https://rp.example.net/logged-out")
				values.Set("state", "state-123")
			},
			expectedStatus:    http.StatusFound,
			expectedRedirect:  "https://rp.example.net/logged-out?state=state-123",
			expectSessionGone: true,
		},
		{
			description: "Rejects an unregistered post-logout redirect URI",
			method:      http.MethodGet,
			configureRequest: func(values url.Values, idToken string) {
				values.Set("id_token_hint", idToken)
				values.Set("post_logout_redirect_uri", "https://evil.example.com/logged-out")
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			description: "Requires confirmation when the ID token hint is missing",
			method:      http.MethodGet,
			configureRequest: func(values url.Values, _ string) {
				values.Set("client_id", "some-client-id")
				values.Set("post_logout_redirect_uri", "https://rp.example.net/logged-out")
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "https://tinyauth.example.com/logout",
		},
		{
			description: "Requires confirmation when client ID does not match the token audience",
			method:      http.MethodGet,
			configureRequest: func(values url.Values, idToken string) {
				values.Set("id_token_hint", idToken)
				values.Set("client_id", "another-client")
				values.Set("post_logout_redirect_uri", "https://rp.example.net/logged-out")
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "https://tinyauth.example.com/logout",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			cfg, runtime := testutil.CreateTestConfigs(t)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			log := logger.NewLogger().WithTestConfig()
			log.Init()
			store := memory.New()
			dg := ding.New(ctx)

			oidcService, err := service.NewOIDCService(service.OIDCServiceInput{
				Log:     log,
				Config:  &cfg,
				Runtime: &runtime,
				Queries: store,
				Ding:    dg,
			})
			require.NoError(t, err)

			policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
				Log:    log,
				Config: &cfg,
			})
			require.NoError(t, err)
			broker := service.NewOAuthBrokerService(service.OAuthBrokerServiceInput{
				Log:     log,
				Runtime: &runtime,
				Ctx:     ctx,
			})
			authService, err := service.NewAuthService(service.AuthServiceInput{
				Log:          log,
				Config:       &cfg,
				Runtime:      &runtime,
				Ctx:          ctx,
				Ding:         dg,
				Queries:      store,
				OAuthBroker:  broker,
				PolicyEngine: policyEngine,
			})
			require.NoError(t, err)

			userContext := newOAuthUserContext("pocketid", "upstream-id-token")
			client, ok := oidcService.GetClient("some-client-id")
			require.True(t, ok)
			sub := oidcService.CreateSub(*userContext, client.ClientID)
			tokenResponse, err := oidcService.GenerateAccessToken(ctx, client, service.AuthorizeCodeEntry{
				Scope: "openid",
				Userinfo: service.UserinfoResponse{
					Sub:               sub,
					Email:             userContext.GetEmail(),
					PreferredUsername: userContext.GetUsername(),
				},
			}, time.Now().Unix())
			require.NoError(t, err)

			_, err = store.CreateSession(ctx, repository.CreateSessionParams{
				UUID:         "browser-session",
				Username:     userContext.GetUsername(),
				Email:        userContext.GetEmail(),
				Name:         userContext.GetName(),
				Provider:     "pocketid",
				Expiry:       time.Now().Add(time.Hour).Unix(),
				CreatedAt:    time.Now().Unix(),
				OAuthName:    "Pocket ID",
				OAuthSub:     "upstream-sub",
				OAuthIDToken: "upstream-id-token",
			})
			require.NoError(t, err)

			if test.provider != nil {
				runtime.OAuthProviders = map[string]model.OAuthServiceConfig{
					"pocketid": *test.provider,
				}
			}

			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("context", userContext)
				c.Next()
			})
			NewOIDCController(OIDCControllerInput{
				Log:           log,
				OIDCService:   oidcService,
				AuthService:   authService,
				RuntimeConfig: &runtime,
				RouterGroup:   router.Group("/api"),
				MainRouter:    &router.RouterGroup,
			})
			NewUserController(UserControllerInput{
				Log:           log,
				StaticConfig:  &cfg,
				RuntimeConfig: &runtime,
				RouterGroup:   router.Group("/api"),
				AuthService:   authService,
			})

			values := url.Values{}
			test.configureRequest(values, tokenResponse.IDToken)
			requestURL := "/api/oidc/end-session"
			var request *http.Request
			if test.method == http.MethodPost {
				request = httptest.NewRequest(test.method, requestURL, strings.NewReader(values.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				request = httptest.NewRequest(test.method, requestURL+"?"+values.Encode(), nil)
			}
			request.AddCookie(&http.Cookie{Name: runtime.SessionCookieName, Value: "browser-session"})

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			assert.Equal(t, test.expectedStatus, recorder.Code)
			if test.expectedRedirect != "" {
				assert.Equal(t, test.expectedRedirect, recorder.Header().Get("Location"))
			}
			if test.validateRedirect != nil {
				test.validateRedirect(t, recorder.Header().Get("Location"))
			}
			if test.expectedCallback != "" {
				providerRedirect, err := url.Parse(recorder.Header().Get("Location"))
				require.NoError(t, err)
				callbackRecorder := httptest.NewRecorder()
				callbackRequest := httptest.NewRequest(
					http.MethodGet,
					"/api/user/logout/callback?state="+url.QueryEscape(providerRedirect.Query().Get("state")),
					nil,
				)
				router.ServeHTTP(callbackRecorder, callbackRequest)
				assert.Equal(t, http.StatusFound, callbackRecorder.Code)
				assert.Equal(t, test.expectedCallback, callbackRecorder.Header().Get("Location"))

				callbackRecorder = httptest.NewRecorder()
				router.ServeHTTP(callbackRecorder, callbackRequest)
				assert.Equal(t, http.StatusFound, callbackRecorder.Code)
				assert.Equal(t, runtime.AppURL, callbackRecorder.Header().Get("Location"))
			}

			_, err = store.GetSession(ctx, "browser-session")
			if test.expectSessionGone {
				require.ErrorIs(t, err, repository.ErrNotFound)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
