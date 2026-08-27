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

func TestSSOLogoutUsesServerSideIDToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)
	runtime.OAuthProviders = map[string]model.OAuthServiceConfig{
		"pocketid": {
			ClientID:  "client-id",
			LogoutURL: "https://id.example.com/api/oidc/end-session",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	store := memory.New()
	_, err := store.CreateSession(ctx, repository.CreateSessionParams{
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
	})
	require.NoError(t, err)

	dg := ding.New(ctx)
	authService, err := service.NewAuthService(service.AuthServiceInput{
		Log:     log,
		Config:  &cfg,
		Runtime: &runtime,
		Ctx:     ctx,
		Ding:    dg,
		Queries: store,
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderOAuth,
			OAuth: &model.OAuthContext{
				BaseContext: model.BaseContext{
					Username: "user@example.com",
					Name:     "Test User",
					Email:    "user@example.com",
				},
				DisplayName: "Pocket ID",
				ID:          "pocketid",
				IDToken:     "id-token",
			},
		})
		c.Next()
	})

	NewUserController(UserControllerInput{
		Log:           log,
		StaticConfig:  &cfg,
		RuntimeConfig: &runtime,
		RouterGroup:   router.Group("/api"),
		AuthService:   authService,
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/user/logout?redirect_uri=https://app.example.com/", nil)
	req.AddCookie(&http.Cookie{
		Name:  runtime.SessionCookieName,
		Value: "oauth-session",
	})

	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Len(t, recorder.Result().Cookies(), 1)
	assert.Equal(t, runtime.SessionCookieName, recorder.Result().Cookies()[0].Name)

	var response struct {
		RedirectURL string `json:"redirectUrl"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
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
}

func TestSSOLogoutFallsBackToRedirectURIWhenProviderLogoutURLIsInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)
	runtime.OAuthProviders = map[string]model.OAuthServiceConfig{
		"pocketid": {
			LogoutURL: "http://id.example.com/api/oidc/end-session",
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderOAuth,
			OAuth: &model.OAuthContext{
				BaseContext: model.BaseContext{
					Username: "user@example.com",
					Name:     "Test User",
					Email:    "user@example.com",
				},
				DisplayName: "Pocket ID",
				ID:          "pocketid",
			},
		})
		c.Next()
	})

	NewUserController(UserControllerInput{
		Log:           log,
		StaticConfig:  &cfg,
		RuntimeConfig: &runtime,
		RouterGroup:   router.Group("/api"),
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/user/logout?redirect_uri=https://app.example.com/", nil)

	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)

	var response struct {
		RedirectURL string `json:"redirectUrl"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "https://app.example.com/", response.RedirectURL)
}

func TestBuildOAuthLogoutURL(t *testing.T) {
	got, err := buildOAuthLogoutURL(
		model.OAuthServiceConfig{
			ClientID:  "client-id",
			LogoutURL: "https://id.example.com/api/oidc/end-session",
		},
		"https://auth.example.com/api/user/logout/callback",
		"id-token",
		"https://app.example.com/",
	)
	require.NoError(t, err)

	parsed, err := url.Parse(got)
	require.NoError(t, err)
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
}

func TestBuildOAuthLogoutURLRejectsHTTP(t *testing.T) {
	_, err := buildOAuthLogoutURL(
		model.OAuthServiceConfig{
			LogoutURL: "http://id.example.com/api/oidc/end-session",
		},
		"https://auth.example.com/api/user/logout/callback",
		"id-token",
		"https://app.example.com/",
	)
	require.Error(t, err)
}
