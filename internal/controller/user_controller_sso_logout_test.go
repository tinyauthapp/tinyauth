package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type logoutResponse struct {
	RedirectURL string `json:"redirectUrl"`
}

func TestSSOLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, runtime := test.CreateTestConfigs(t)

	tests := []struct {
		description string
		provider    model.OAuthServiceConfig
		session     *repository.CreateSessionParams
		userContext *model.UserContext
		requestPath string
		validate    func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			description: "Uses context ID token for provider logout",
			provider: model.OAuthServiceConfig{
				ClientID:  "client-id",
				LogoutURL: "https://id.example.com/api/oidc/end-session",
			},
			session: &repository.CreateSessionParams{
				UUID:         "oauth-session",
				Username:     "user@example.com",
				Email:        "user@example.com",
				Name:         "Test User",
				Provider:     "pocketid",
				OAuthGroups:  "admins",
				Expiry:       time.Now().Add(time.Hour).Unix(),
				CreatedAt:    time.Now().Unix(),
				OAuthName:    "Pocket ID",
				OAuthSub:     "sub-123",
				OAuthIDToken: "id-token",
			},
			userContext: newOAuthUserContext("pocketid", "id-token"),
			requestPath: "/api/user/logout?login_for=app&redirect_uri=https://app.example.com/",
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Len(t, recorder.Result().Cookies(), 1)
				assert.Equal(t, "tinyauth-session", recorder.Result().Cookies()[0].Name)

				response := parseLogoutResponse(t, recorder)
				require.NotEmpty(t, response.RedirectURL)

				parsed, err := url.Parse(response.RedirectURL)
				require.NoError(t, err)
				assert.Equal(t, "https", parsed.Scheme)
				assert.Equal(t, "id.example.com", parsed.Host)
				assert.Equal(t, "id-token", parsed.Query().Get("id_token_hint"))
				assert.Equal(t, "client-id", parsed.Query().Get("client_id"))
				assert.Equal(t, "https://app.example.com/", parsed.Query().Get("state"))
				assert.Equal(
					t,
					"https://tinyauth.example.com/api/user/logout/callback",
					parsed.Query().Get("post_logout_redirect_uri"),
				)
			},
		},
		{
			description: "Falls back to app redirect when provider logout URL is invalid",
			provider: model.OAuthServiceConfig{
				LogoutURL: "http://id.example.com/api/oidc/end-session",
			},
			userContext: newOAuthUserContext("pocketid", ""),
			requestPath: "/api/user/logout?login_for=app&redirect_uri=https://app.example.com/",
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)

				response := parseLogoutResponse(t, recorder)
				assert.Equal(t, "https://app.example.com/", response.RedirectURL)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			log := logger.NewLogger().WithTestConfig()
			log.Init()

			runtime.OAuthProviders = map[string]model.OAuthServiceConfig{
				"pocketid": test.provider,
			}

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			store := memory.New()
			var authService *service.AuthService
			if test.session != nil {
				_, err := store.CreateSession(ctx, *test.session)
				require.NoError(t, err)

				dg := ding.New(ctx)
				authService, err = service.NewAuthService(service.AuthServiceInput{
					Log:     log,
					Config:  &cfg,
					Runtime: &runtime,
					Ctx:     ctx,
					Ding:    dg,
					Queries: store,
				})
				require.NoError(t, err)
			}

			router := gin.New()
			if test.userContext != nil {
				router.Use(func(c *gin.Context) {
					c.Set("context", test.userContext)
					c.Next()
				})
			}

			NewUserController(UserControllerInput{
				Log:           log,
				StaticConfig:  &cfg,
				RuntimeConfig: &runtime,
				RouterGroup:   router.Group("/api"),
				AuthService:   authService,
			})

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, test.requestPath, nil)
			if test.session != nil {
				req.AddCookie(&http.Cookie{
					Name:  runtime.SessionCookieName,
					Value: test.session.UUID,
				})
			}

			router.ServeHTTP(recorder, req)

			test.validate(t, recorder)
		})
	}
}

func TestBuildOAuthLogoutURL(t *testing.T) {
	tests := []struct {
		description string
		provider    model.OAuthServiceConfig
		expectError bool
		validate    func(t *testing.T, parsed *url.URL)
	}{
		{
			description: "Builds provider logout URL with OIDC logout parameters",
			provider: model.OAuthServiceConfig{
				ClientID:  "client-id",
				LogoutURL: "https://id.example.com/api/oidc/end-session",
			},
			validate: func(t *testing.T, parsed *url.URL) {
				assert.Equal(t, "https", parsed.Scheme)
				assert.Equal(t, "id.example.com", parsed.Host)
				assert.Equal(t, "/api/oidc/end-session", parsed.Path)
				assert.Equal(t, "client-id", parsed.Query().Get("client_id"))
				assert.Equal(t, "id-token", parsed.Query().Get("id_token_hint"))
				assert.Equal(t, "https://app.example.com/", parsed.Query().Get("state"))
				assert.Equal(
					t,
					"https://auth.example.com/api/user/logout/callback",
					parsed.Query().Get("post_logout_redirect_uri"),
				)
			},
		},
		{
			description: "Rejects HTTP provider logout URL",
			provider: model.OAuthServiceConfig{
				LogoutURL: "http://id.example.com/api/oidc/end-session",
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got, err := buildOAuthLogoutURL(
				test.provider,
				"https://auth.example.com/api/user/logout/callback",
				"id-token",
				"https://app.example.com/",
			)
			if test.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			parsed, err := url.Parse(got)
			require.NoError(t, err)
			test.validate(t, parsed)
		})
	}
}

func newOAuthUserContext(providerID, idToken string) *model.UserContext {
	return &model.UserContext{
		Authenticated: true,
		Provider:      model.ProviderOAuth,
		OAuth: &model.OAuthContext{
			BaseContext: model.BaseContext{
				Username: "user@example.com",
				Name:     "Test User",
				Email:    "user@example.com",
			},
			DisplayName: "Pocket ID",
			ID:          providerID,
			IDToken:     idToken,
		},
	}
}

func parseLogoutResponse(t *testing.T, recorder *httptest.ResponseRecorder) logoutResponse {
	t.Helper()

	var response logoutResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}
