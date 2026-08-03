package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

func TestOIDCController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	ctx := context.TODO()
	dg := ding.New(ctx)

	store := memory.New()

	oidcService, err := service.NewOIDCService(service.OIDCServiceInput{
		Log:     log,
		Config:  &cfg,
		Runtime: &runtime,
		Queries: store,
		Ding:    dg,
	})
	require.NoError(t, err)

	// Middleware that injects an authenticated local user into the gin context,
	// mimicking the context middleware that runs before the OIDC
	authedUser := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "testuser",
					Name:     "Test User",
					Email:    "testuser@example.com",
				},
			},
		})
	}

	type testCase struct {
		description  string
		middlewares  []gin.HandlerFunc
		oidcDisabled bool
		run          func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		// --- authorize ---
		{
			description:  "Authorize redirects to error screen when OIDC is not configured",
			oidcDisabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/authorize", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, runtime.AppURL+"/error")
				assert.Contains(t, location, url.QueryEscape("This instance is not configured for OIDC"))
			},
		},
		{
			description: "Authorize redirects to error screen when query parameters are missing",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/authorize", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, oidcService.GetIssuer()+"/error")
				assert.Contains(t, location, url.QueryEscape("The client ID is invalid"))
			},
		},
		{
			description: "Authorize redirects to error screen when client is unknown",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				q := url.Values{}
				q.Set("scope", "openid")
				q.Set("response_type", "code")
				q.Set("client_id", "unknown-client")
				q.Set("redirect_uri", "https://test.example.com/callback")

				req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, oidcService.GetIssuer()+"/error")
				assert.Contains(t, location, url.QueryEscape("The client ID is invalid"))
			},
		},
		{
			description: "Authorize redirects to error screen when redirect URI is not trusted",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				q := url.Values{}
				q.Set("scope", "openid")
				q.Set("response_type", "code")
				q.Set("client_id", "some-client-id")
				q.Set("redirect_uri", "https://evil.example.com/callback")

				req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, oidcService.GetIssuer()+"/error")
				assert.Contains(t, location, url.QueryEscape("The provided redirect URI is not trusted"))
			},
		},
		{
			description: "Authorize redirects to callback with error when params are invalid",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				q := url.Values{}
				q.Set("scope", "openid")
				q.Set("response_type", "token") // unsupported response type
				q.Set("client_id", "some-client-id")
				q.Set("redirect_uri", "https://test.example.com/callback")
				q.Set("state", "state-123")

				req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.True(t, strings.HasPrefix(location, "https://test.example.com/callback?"))
				assert.Contains(t, location, "error=unsupported_response_type")
				assert.Contains(t, location, "state=state-123")
			},
		},
		{
			description: "Authorize redirects to consent screen on a valid request",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				q := url.Values{}
				q.Set("scope", "openid profile")
				q.Set("response_type", "code")
				q.Set("client_id", "some-client-id")
				q.Set("redirect_uri", "https://test.example.com/callback")
				q.Set("state", "state-123")

				req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.True(t, strings.HasPrefix(location, oidcService.GetIssuer()+"/oidc/authorize?"))
				assert.Contains(t, location, "login_for=oidc")
				assert.Contains(t, location, "oidc_ticket=")
				assert.Contains(t, location, "oidc_name="+url.QueryEscape("Test Client"))
			},
		},
		{
			description: "Authorize redirects to error screen when the request object is invalid",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/authorize?request=not-a-valid-jwt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, oidcService.GetIssuer()+"/error")
				assert.Contains(t, location, url.QueryEscape("The authorization request is invalid"))
			},
		},
		{
			description: "Authorize accepts a request object and redirects to the consent screen",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
					"scope":         "openid profile",
					"response_type": "code",
					"client_id":     "some-client-id",
					"redirect_uri":  "https://test.example.com/callback",
					"state":         "state-123",
				})
				signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				require.NoError(t, err)

				q := url.Values{}
				q.Set("request", signed)

				req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.True(t, strings.HasPrefix(location, oidcService.GetIssuer()+"/oidc/authorize?"))
				assert.Contains(t, location, "oidc_ticket=")
			},
		},

		// --- authorize-complete ---
		{
			description:  "Should fail if oidc is disabled",
			oidcDisabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				body, err := json.Marshal(AuthorizeCompleteRequest{Ticket: "some-ticket"})
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize-complete", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				redirectURI, ok := res["redirect_uri"].(string)
				require.True(t, ok)
				assert.Contains(t, redirectURI, oidcService.GetIssuer()+"/error")
			},
		},
		{
			description: "Authorize complete returns a JSON error when the user context is missing",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				body, err := json.Marshal(AuthorizeCompleteRequest{Ticket: "some-ticket"})
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize-complete", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				redirectURI, ok := res["redirect_uri"].(string)
				require.True(t, ok)
				assert.Contains(t, redirectURI, oidcService.GetIssuer()+"/error")
			},
		},
		{
			description: "Authorize complete returns a JSON error when the user is not authenticated",
			middlewares: []gin.HandlerFunc{
				func(c *gin.Context) {
					c.Set("context", &model.UserContext{
						Authenticated: false,
						Provider:      model.ProviderLocal,
						Local: &model.LocalContext{
							BaseContext: model.BaseContext{Username: "testuser"},
						},
					})
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				body, err := json.Marshal(AuthorizeCompleteRequest{Ticket: "some-ticket"})
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize-complete", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				redirectURI, ok := res["redirect_uri"].(string)
				require.True(t, ok)
				assert.Contains(t, redirectURI, oidcService.GetIssuer()+"/error")
			},
		},
		{
			description: "Authorize complete returns a JSON error when the ticket is invalid",
			middlewares: []gin.HandlerFunc{authedUser},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				body, err := json.Marshal(AuthorizeCompleteRequest{Ticket: "nonexistent-ticket"})
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize-complete", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				redirectURI, ok := res["redirect_uri"].(string)
				require.True(t, ok)
				assert.Contains(t, redirectURI, oidcService.GetIssuer()+"/error")
			},
		},
		{
			description: "Authorize complete returns a redirect URI with a code on success",
			middlewares: []gin.HandlerFunc{authedUser},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				ticket := oidcService.CreateAuthorizeRequestTicket(service.AuthorizeRequest{
					Scope:        "openid profile",
					ResponseType: "code",
					ClientID:     "some-client-id",
					RedirectURI:  "https://test.example.com/callback",
					State:        "state-123",
				})

				body, err := json.Marshal(AuthorizeCompleteRequest{Ticket: ticket})
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize-complete", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				redirectURI, ok := res["redirect_uri"].(string)
				require.True(t, ok)
				assert.True(t, strings.HasPrefix(redirectURI, "https://test.example.com/callback?code="))
				assert.Contains(t, redirectURI, "state=state-123")
			},
		},

		// --- token ---
		{
			description:  "Token returns 500 when OIDC is not configured",
			oidcDisabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/token", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusInternalServerError, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "server_error")
			},
		},
		{
			description: "Token returns 400 when the grant type is missing",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(""))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			description: "Token returns 400 when the grant type is unsupported",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "password")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "unsupported_grant_type")
			},
		},
		{
			description: "Token returns 400 and a challenge when client credentials are missing",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "authorization_code")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_client")
				assert.NotEmpty(t, recorder.Header().Get("www-authenticate"))
			},
		},
		{
			description: "Token returns 400 when the client is unknown",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "unknown-client")
				form.Set("client_secret", "whatever")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_client")
			},
		},
		{
			description: "Token returns 400 when the client secret is wrong",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "wrong-secret")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_client")
			},
		},
		{
			description: "Token returns 400 when the authorization code is unknown",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("code", "unknown-code")
				form.Set("redirect_uri", "https://test.example.com/callback")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_grant")
			},
		},
		{
			description: "Token returns 400 when the redirect URI does not match the code",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				code := oidcService.CreateCode(service.AuthorizeRequest{
					Scope:        "openid",
					ResponseType: "code",
					ClientID:     "some-client-id",
					RedirectURI:  "https://test.example.com/callback",
				}, model.UserContext{
					Authenticated: true,
					Provider:      model.ProviderLocal,
					Local:         &model.LocalContext{BaseContext: model.BaseContext{Username: "testuser"}},
				})

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("code", code)
				form.Set("redirect_uri", "https://test.example.com/different")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_grant")
			},
		},
		{
			description: "Token exchanges an authorization code for tokens",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				code := oidcService.CreateCode(service.AuthorizeRequest{
					Scope:        "openid profile email",
					ResponseType: "code",
					ClientID:     "some-client-id",
					RedirectURI:  "https://test.example.com/callback",
				}, model.UserContext{
					Authenticated: true,
					Provider:      model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{
							Username: "testuser",
							Name:     "Test User",
							Email:    "testuser@example.com",
						},
					},
				})

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("code", code)
				form.Set("redirect_uri", "https://test.example.com/callback")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "no-store", recorder.Header().Get("cache-control"))

				var res service.TokenResponse
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				assert.NotEmpty(t, res.AccessToken)
				assert.NotEmpty(t, res.RefreshToken)
				assert.NotEmpty(t, res.IDToken)
				assert.Equal(t, "Bearer", res.TokenType)
			},
		},
		{
			description: "Token deletes the session and returns invalid_grant when a code is reused",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				expiry := time.Now().Add(time.Hour).Unix()
				sub := "reused-code-sub"

				_, err := store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   sub,
					AccessTokenHash:       "reused-access-hash",
					RefreshTokenHash:      "reused-refresh-hash",
					Scope:                 "openid",
					ClientID:              "some-client-id",
					TokenExpiresAt:        expiry,
					RefreshTokenExpiresAt: expiry,
					UserinfoJson:          "{}",
				})
				require.NoError(t, err)

				oidcService.MarkCodeAsUsed(oidcService.Hash("reused-code"), sub)

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("code", "reused-code")
				form.Set("redirect_uri", "https://test.example.com/callback")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_grant")

				// The session associated with the reused code should be revoked.
				_, err = store.GetOIDCSessionBySub(ctx, sub)
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Token refreshes an access token using a refresh token",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				expiry := time.Now().Add(time.Hour).Unix()

				_, err := store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   "refresh-sub",
					AccessTokenHash:       "refresh-access-hash",
					RefreshTokenHash:      oidcService.Hash("valid-refresh-token"),
					Scope:                 "openid profile",
					ClientID:              "some-client-id",
					TokenExpiresAt:        expiry,
					RefreshTokenExpiresAt: expiry,
					UserinfoJson:          `{"sub":"refresh-sub"}`,
				})
				require.NoError(t, err)

				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("refresh_token", "valid-refresh-token")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res service.TokenResponse
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				assert.NotEmpty(t, res.AccessToken)
				assert.NotEmpty(t, res.RefreshToken)
				assert.NotEqual(t, "valid-refresh-token", res.RefreshToken)
			},
		},
		{
			description: "Token returns invalid_grant when the refresh token is expired",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				past := time.Now().Add(-time.Hour).Unix()

				_, err := store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   "expired-refresh-sub",
					AccessTokenHash:       "expired-access-hash",
					RefreshTokenHash:      oidcService.Hash("expired-refresh-token"),
					Scope:                 "openid",
					ClientID:              "some-client-id",
					TokenExpiresAt:        past,
					RefreshTokenExpiresAt: past,
					UserinfoJson:          "{}",
				})
				require.NoError(t, err)

				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("refresh_token", "expired-refresh-token")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_grant")
			},
		},
		{
			description: "Token returns invalid_grant when the refresh token belongs to another client",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				expiry := time.Now().Add(time.Hour).Unix()

				_, err := store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   "other-client-sub",
					AccessTokenHash:       "other-client-access-hash",
					RefreshTokenHash:      oidcService.Hash("other-client-refresh-token"),
					Scope:                 "openid",
					ClientID:              "other-client-id",
					TokenExpiresAt:        expiry,
					RefreshTokenExpiresAt: expiry,
					UserinfoJson:          "{}",
				})
				require.NoError(t, err)

				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("refresh_token", "other-client-refresh-token")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_grant")
			},
		},
		{
			description: "Token returns server_error when the refresh token is unknown",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")
				form.Set("refresh_token", "nonexistent-refresh-token")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "server_error")
			},
		},

		// --- userinfo ---
		{
			description:  "Userinfo returns 500 when OIDC is not configured",
			oidcDisabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusInternalServerError, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "server_error")
			},
		},
		{
			description: "Userinfo returns 401 when the authorization header is malformed",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "malformedheader")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			description: "Userinfo returns 401 when the token type is not bearer",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Basic some-token")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			description: "Userinfo returns 401 when there is no authorization header on a GET",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			description: "Userinfo returns 400 when a POST has the wrong content type",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/userinfo", strings.NewReader(`{"access_token":"x"}`))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			description: "Userinfo returns 401 when a POST has no access token",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/userinfo", strings.NewReader(""))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			description: "Userinfo returns 401 when the token is unknown",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer unknown-token")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_grant")
			},
		},
		{
			description: "Userinfo returns 401 when the session is missing the openid scope",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				expiry := time.Now().Add(time.Hour).Unix()
				token := "no-openid-token"

				_, err := store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   "no-openid-sub",
					AccessTokenHash:       oidcService.Hash(token),
					RefreshTokenHash:      "no-openid-refresh-hash",
					Scope:                 "profile email",
					ClientID:              "some-client-id",
					TokenExpiresAt:        expiry,
					RefreshTokenExpiresAt: expiry,
					UserinfoJson:          `{"sub":"no-openid-sub"}`,
				})
				require.NoError(t, err)

				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid_scope")
			},
		},
		{
			description: "Userinfo returns the user info for a valid bearer token",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				expiry := time.Now().Add(time.Hour).Unix()
				token := "valid-userinfo-token"

				userinfo, err := json.Marshal(service.UserinfoResponse{
					Sub:               "userinfo-sub",
					Name:              "Test User",
					PreferredUsername: "testuser",
					Email:             "testuser@example.com",
				})
				require.NoError(t, err)

				_, err = store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   "userinfo-sub",
					AccessTokenHash:       oidcService.Hash(token),
					RefreshTokenHash:      "valid-userinfo-refresh-hash",
					Scope:                 "openid profile email",
					ClientID:              "some-client-id",
					TokenExpiresAt:        expiry,
					RefreshTokenExpiresAt: expiry,
					UserinfoJson:          string(userinfo),
				})
				require.NoError(t, err)

				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res service.UserinfoResponse
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				assert.Equal(t, "userinfo-sub", res.Sub)
				assert.Equal(t, "Test User", res.Name)
				assert.Equal(t, "testuser@example.com", res.Email)
				assert.True(t, res.EmailVerified)
			},
		},
		{
			description: "Userinfo returns the user info for a valid POST access token",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				expiry := time.Now().Add(time.Hour).Unix()
				token := "valid-userinfo-post-token"

				userinfo, err := json.Marshal(service.UserinfoResponse{
					Sub:   "userinfo-post-sub",
					Email: "testuser@example.com",
				})
				require.NoError(t, err)

				_, err = store.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:                   "userinfo-post-sub",
					AccessTokenHash:       oidcService.Hash(token),
					RefreshTokenHash:      "valid-userinfo-post-refresh-hash",
					Scope:                 "openid email",
					ClientID:              "some-client-id",
					TokenExpiresAt:        expiry,
					RefreshTokenExpiresAt: expiry,
					UserinfoJson:          string(userinfo),
				})
				require.NoError(t, err)

				form := url.Values{}
				form.Set("access_token", token)

				req := httptest.NewRequest("POST", "/api/oidc/userinfo", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)

				var res service.UserinfoResponse
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				assert.Equal(t, "userinfo-post-sub", res.Sub)
				assert.Equal(t, "testuser@example.com", res.Email)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			gin.SetMode(gin.TestMode)

			for _, middleware := range test.middlewares {
				router.Use(middleware)
			}

			group := router.Group("/api")

			svc := oidcService
			if test.oidcDisabled {
				svc = nil
			}

			NewOIDCController(OIDCControllerInput{
				Log:           log,
				OIDCService:   svc,
				RuntimeConfig: &runtime,
				RouterGroup:   group,
				MainRouter:    &router.RouterGroup,
			})

			recorder := httptest.NewRecorder()

			test.run(t, router, recorder)
		})
	}
}
