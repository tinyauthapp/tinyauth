package controller_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCController(t *testing.T) {
	tlog.NewTestLogger().Init()
	tempDir := t.TempDir()

	oidcServiceCfg := service.OIDCServiceConfig{
		Clients: map[string]config.OIDCClientConfig{
			"test": {
				ClientID:            "some-client-id",
				ClientSecret:        "some-client-secret",
				TrustedRedirectURIs: []string{"https://test.example.com/callback"},
				Name:                "Test Client",
			},
		},
		PrivateKeyPath: path.Join(tempDir, "key.pem"),
		PublicKeyPath:  path.Join(tempDir, "key.pub"),
		Issuer:         "https://tinyauth.example.com",
		SessionExpiry:  500,
	}

	controllerCfg := controller.OIDCControllerConfig{}

	simpleCtx := func(c *gin.Context) {
		c.Set("context", &config.UserContext{
			Username:   "test",
			Name:       "Test User",
			Email:      "test@example.com",
			IsLoggedIn: true,
			Provider:   "local",
		})
		c.Next()
	}

	type testCase struct {
		description string
		middlewares []gin.HandlerFunc
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	var tests []testCase

	getTestByDescription := func(description string) (func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder), bool) {
		for _, test := range tests {
			if test.description == description {
				return test.run, true
			}
		}
		return nil, false
	}

	tests = []testCase{
		{
			description: "Ensure we can fetch the client",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/clients/some-client-id", nil)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure API fails on non-existent client ID",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/clients/non-existent-client-id", nil)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 404, recorder.Code)
			},
		},
		{
			description: "Ensure authorize fails with empty context",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/authorize", nil)
				router.ServeHTTP(recorder, req)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				assert.Equal(t, res["redirect_uri"], "https://tinyauth.example.com/error?error=User+is+not+logged+in+or+the+session+is+invalid")
			},
		},
		{
			description: "Ensure authorize fails with an invalid param",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				reqBody := service.AuthorizeRequest{
					Scope:        "openid",
					ResponseType: "some_unsupported_response_type",
					ClientID:     "some-client-id",
					RedirectURI:  "https://test.example.com/callback",
					State:        "some-state",
					Nonce:        "some-nonce",
				}
				reqBodyBytes, err := json.Marshal(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(reqBodyBytes)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				assert.Equal(t, res["redirect_uri"], "https://test.example.com/callback?error=unsupported_response_type&error_description=Invalid+request+parameters&state=some-state")
			},
		},
		{
			description: "Ensure authorize succeeds with valid params",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				reqBody := service.AuthorizeRequest{
					Scope:        "openid",
					ResponseType: "code",
					ClientID:     "some-client-id",
					RedirectURI:  "https://test.example.com/callback",
					State:        "some-state",
					Nonce:        "some-nonce",
				}
				reqBodyBytes, err := json.Marshal(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(reqBodyBytes)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				redirectURI := res["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				assert.Equal(t, queryParams.Get("state"), "some-state")

				code := queryParams.Get("code")
				assert.NotEmpty(t, code)
			},
		},
		{
			description: "Ensure token request fails with invalid grant",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				reqBody := controller.TokenRequest{
					GrantType:   "invalid_grant",
					Code:        "",
					RedirectURI: "https://test.example.com/callback",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				assert.Equal(t, res["error"], "unsupported_grant_type")
			},
		},
		{
			description: "Ensure token endpoint accepts basic auth",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				reqBody := controller.TokenRequest{
					GrantType:   "authorization_code",
					Code:        "some-code",
					RedirectURI: "https://test.example.com/callback",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				router.ServeHTTP(recorder, req)

				assert.Empty(t, recorder.Header().Get("www-authenticate"))
			},
		},
		{
			description: "Ensure token endpoint accepts form auth",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", "some-code")
				form.Set("redirect_uri", "https://test.example.com/callback")
				form.Set("client_id", "some-client-id")
				form.Set("client_secret", "some-client-secret")

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.Empty(t, recorder.Header().Get("www-authenticate"))
			},
		},
		{
			description: "Ensure token endpoint sets authenticate header when no auth is available",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				reqBody := controller.TokenRequest{
					GrantType:   "authorization_code",
					Code:        "some-code",
					RedirectURI: "https://test.example.com/callback",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				authHeader := recorder.Header().Get("www-authenticate")
				assert.Contains(t, authHeader, "Basic")
			},
		},
		{
			description: "Ensure we can get a token with a valid request",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				authorizeCodeTest, found := getTestByDescription("Ensure authorize succeeds with valid params")
				assert.True(t, found, "Authorize test not found")
				authorizeTestRecorder := httptest.NewRecorder()
				authorizeCodeTest(t, router, authorizeTestRecorder)

				var authorizeRes map[string]any
				err := json.Unmarshal(authorizeTestRecorder.Body.Bytes(), &authorizeRes)
				assert.NoError(t, err)

				redirectURI := authorizeRes["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				code := queryParams.Get("code")
				assert.NotEmpty(t, code)

				reqBody := controller.TokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "https://test.example.com/callback",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure we can renew the access token with the refresh token",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				tokenTest, found := getTestByDescription("Ensure we can get a token with a valid request")
				assert.True(t, found, "Token test not found")
				tokenRecorder := httptest.NewRecorder()
				tokenTest(t, router, tokenRecorder)

				var tokenRes map[string]any
				err := json.Unmarshal(tokenRecorder.Body.Bytes(), &tokenRes)
				assert.NoError(t, err)

				_, ok := tokenRes["refresh_token"]
				assert.True(t, ok, "Expected refresh token in response")
				refreshToken := tokenRes["refresh_token"].(string)
				assert.NotEmpty(t, refreshToken)

				reqBody := controller.TokenRequest{
					GrantType:    "refresh_token",
					RefreshToken: refreshToken,
					ClientID:     "some-client-id",
					ClientSecret: "some-client-secret",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)

				assert.NotEmpty(t, recorder.Header().Get("cache-control"))
				assert.NotEmpty(t, recorder.Header().Get("pragma"))

				assert.Equal(t, 200, recorder.Code)
				var refreshRes map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &refreshRes)
				assert.NoError(t, err)

				_, ok = refreshRes["access_token"]
				assert.True(t, ok, "Expected access token in refresh response")
				assert.NotEqual(t, tokenRes["refresh_token"].(string), refreshRes["access_token"].(string))
				assert.NotEqual(t, tokenRes["access_token"].(string), refreshRes["access_token"].(string))
			},
		},
		{
			description: "Ensure token endpoint deletes code after use",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				authorizeCodeTest, found := getTestByDescription("Ensure authorize succeeds with valid params")
				assert.True(t, found, "Authorize test not found")
				authorizeTestRecorder := httptest.NewRecorder()
				authorizeCodeTest(t, router, authorizeTestRecorder)

				var authorizeRes map[string]any
				err := json.Unmarshal(authorizeTestRecorder.Body.Bytes(), &authorizeRes)
				assert.NoError(t, err)

				redirectURI := authorizeRes["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				code := queryParams.Get("code")
				assert.NotEmpty(t, code)

				reqBody := controller.TokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "https://test.example.com/callback",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				// Try to use the same code again
				secondReq := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				secondReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				secondReq.SetBasicAuth("some-client-id", "some-client-secret")
				secondRecorder := httptest.NewRecorder()
				router.ServeHTTP(secondRecorder, secondReq)

				assert.Equal(t, 400, secondRecorder.Code)

				var secondRes map[string]any
				err = json.Unmarshal(secondRecorder.Body.Bytes(), &secondRes)
				assert.NoError(t, err)

				assert.Equal(t, "invalid_grant", secondRes["error"])
			},
		},
		{
			description: "Ensure userinfo forbids access with invalid access token",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer invalid-access-token")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)
			},
		},
		{
			description: "Ensure access token can be used to access protected resources",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				tokenTest, found := getTestByDescription("Ensure we can get a token with a valid request")
				assert.True(t, found, "Token test not found")
				tokenRecorder := httptest.NewRecorder()
				tokenTest(t, router, tokenRecorder)

				var tokenRes map[string]any
				err := json.Unmarshal(tokenRecorder.Body.Bytes(), &tokenRes)
				assert.NoError(t, err)

				accessToken := tokenRes["access_token"].(string)
				assert.NotEmpty(t, accessToken)

				protectedReq := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				protectedReq.Header.Set("Authorization", "Bearer "+accessToken)
				router.ServeHTTP(recorder, protectedReq)
				assert.Equal(t, 200, recorder.Code)

				var userInfoRes map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &userInfoRes)
				assert.NoError(t, err)

				_, ok := userInfoRes["sub"]
				assert.True(t, ok, "Expected sub claim in userinfo response")

				// We should not have an email claim since we didn't request it in the scope
				_, ok = userInfoRes["email"]
				assert.False(t, ok, "Did not expect email claim in userinfo response")
			},
		},
		{
			description: "Ensure userinfo forbids access with no authorization header",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_request", res["error"])
			},
		},
		{
			description: "Ensure userinfo forbids access with malformed authorization header",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_request", res["error"])
			},
		},
		{
			description: "Ensure userinfo forbids access with invalid token type",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Basic some-token")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_request", res["error"])
			},
		},
		{
			description: "Ensure userinfo forbids access with empty bearer token",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer ")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_grant", res["error"])
			},
		},
		{
			description: "Ensure userinfo POST rejects missing access token in body",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/userinfo", strings.NewReader(""))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_request", res["error"])
			},
		},
		{
			description: "Ensure userinfo POST rejects wrong content type",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("POST", "/api/oidc/userinfo", strings.NewReader(`{"access_token":"some-token"}`))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 400, recorder.Code)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_request", res["error"])
			},
		},
		{
			description: "Ensure userinfo accepts access token via POST body",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				tokenTest, found := getTestByDescription("Ensure we can get a token with a valid request")
				assert.True(t, found, "Token test not found")
				tokenRecorder := httptest.NewRecorder()
				tokenTest(t, router, tokenRecorder)

				var tokenRes map[string]any
				err := json.Unmarshal(tokenRecorder.Body.Bytes(), &tokenRes)
				assert.NoError(t, err)

				accessToken := tokenRes["access_token"].(string)
				assert.NotEmpty(t, accessToken)

				body := url.Values{}
				body.Set("access_token", accessToken)
				req := httptest.NewRequest("POST", "/api/oidc/userinfo", strings.NewReader(body.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				var userInfoRes map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &userInfoRes)
				assert.NoError(t, err)

				_, ok := userInfoRes["sub"]
				assert.True(t, ok, "Expected sub claim in userinfo response")
			},
		},
		{
			description: "Ensure plain PKCE succeeds",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				reqBody := service.AuthorizeRequest{
					Scope:         "openid",
					ResponseType:  "code",
					ClientID:      "some-client-id",
					RedirectURI:   "https://test.example.com/callback",
					State:         "some-state",
					Nonce:         "some-nonce",
					CodeChallenge: "some-challenge",
					// Not setting a code challenge method should default to "plain"
					CodeChallengeMethod: "",
				}
				reqBodyBytes, err := json.Marshal(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(reqBodyBytes)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				redirectURI := res["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				assert.Equal(t, queryParams.Get("state"), "some-state")

				code := queryParams.Get("code")
				assert.NotEmpty(t, code)

				// Now exchange the code for a token
				recorder = httptest.NewRecorder()
				tokenReqBody := controller.TokenRequest{
					GrantType:    "authorization_code",
					Code:         code,
					RedirectURI:  "https://test.example.com/callback",
					CodeVerifier: "some-challenge",
				}
				reqBodyEncoded, err := query.Values(tokenReqBody)
				assert.NoError(t, err)

				req = httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure S256 PKCE succeeds",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				hasher := sha256.New()
				hasher.Write([]byte("some-challenge"))
				codeChallenge := hasher.Sum(nil)
				codeChallengeEncoded := base64.RawURLEncoding.EncodeToString(codeChallenge)
				reqBody := service.AuthorizeRequest{
					Scope:               "openid",
					ResponseType:        "code",
					ClientID:            "some-client-id",
					RedirectURI:         "https://test.example.com/callback",
					State:               "some-state",
					Nonce:               "some-nonce",
					CodeChallenge:       codeChallengeEncoded,
					CodeChallengeMethod: "S256",
				}
				reqBodyBytes, err := json.Marshal(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(reqBodyBytes)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				redirectURI := res["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				assert.Equal(t, queryParams.Get("state"), "some-state")

				code := queryParams.Get("code")
				assert.NotEmpty(t, code)

				// Now exchange the code for a token
				recorder = httptest.NewRecorder()
				tokenReqBody := controller.TokenRequest{
					GrantType:    "authorization_code",
					Code:         code,
					RedirectURI:  "https://test.example.com/callback",
					CodeVerifier: "some-challenge",
				}
				reqBodyEncoded, err := query.Values(tokenReqBody)
				assert.NoError(t, err)

				req = httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure request with invalid PKCE fails",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				hasher := sha256.New()
				hasher.Write([]byte("some-challenge"))
				codeChallenge := hasher.Sum(nil)
				codeChallengeEncoded := base64.RawURLEncoding.EncodeToString(codeChallenge)
				reqBody := service.AuthorizeRequest{
					Scope:               "openid",
					ResponseType:        "code",
					ClientID:            "some-client-id",
					RedirectURI:         "https://test.example.com/callback",
					State:               "some-state",
					Nonce:               "some-nonce",
					CodeChallenge:       codeChallengeEncoded,
					CodeChallengeMethod: "S256",
				}
				reqBodyBytes, err := json.Marshal(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(reqBodyBytes)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				redirectURI := res["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				assert.Equal(t, queryParams.Get("state"), "some-state")

				code := queryParams.Get("code")
				assert.NotEmpty(t, code)

				// Now exchange the code for a token
				recorder = httptest.NewRecorder()
				tokenReqBody := controller.TokenRequest{
					GrantType:    "authorization_code",
					Code:         code,
					RedirectURI:  "https://test.example.com/callback",
					CodeVerifier: "some-challenge-1",
				}
				reqBodyEncoded, err := query.Values(tokenReqBody)
				assert.NoError(t, err)

				req = httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 400, recorder.Code)
			},
		},
		{
			description: "Ensure request with invalid challenge method fails",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				hasher := sha256.New()
				hasher.Write([]byte("some-challenge"))
				codeChallenge := hasher.Sum(nil)
				codeChallengeEncoded := base64.RawURLEncoding.EncodeToString(codeChallenge)
				reqBody := service.AuthorizeRequest{
					Scope:               "openid",
					ResponseType:        "code",
					ClientID:            "some-client-id",
					RedirectURI:         "https://test.example.com/callback",
					State:               "some-state",
					Nonce:               "some-nonce",
					CodeChallenge:       codeChallengeEncoded,
					CodeChallengeMethod: "foo",
				}
				reqBodyBytes, err := json.Marshal(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(reqBodyBytes)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				var res map[string]any
				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				redirectURI := res["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				error := queryParams.Get("error")
				assert.NotEmpty(t, error)
			},
		},
		{
			description: "Ensure access token gets invalidated on double code use",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				authorizeCodeTest, found := getTestByDescription("Ensure authorize succeeds with valid params")
				assert.True(t, found, "Authorize test not found")
				authorizeCodeTest(t, router, recorder)

				var res map[string]any
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				redirectURI := res["redirect_uri"].(string)
				url, err := url.Parse(redirectURI)
				assert.NoError(t, err)

				queryParams := url.Query()
				code := queryParams.Get("code")
				assert.NotEmpty(t, code)

				reqBody := controller.TokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "https://test.example.com/callback",
				}
				reqBodyEncoded, err := query.Values(reqBody)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				recorder = httptest.NewRecorder()
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				accessToken := res["access_token"].(string)
				assert.NotEmpty(t, accessToken)

				req = httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+accessToken)
				recorder = httptest.NewRecorder()
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)

				req = httptest.NewRequest("POST", "/api/oidc/token", strings.NewReader(reqBodyEncoded.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("some-client-id", "some-client-secret")
				recorder = httptest.NewRecorder()
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 400, recorder.Code)

				req = httptest.NewRequest("GET", "/api/oidc/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+accessToken)
				recorder = httptest.NewRecorder()
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)

				err = json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "invalid_grant", res["error"])
			},
		},
	}

	app := bootstrap.NewBootstrapApp(config.Config{})

	db, err := app.SetupDatabase(path.Join(tempDir, "tinyauth.db"))
	require.NoError(t, err)

	queries := repository.New(db)
	oidcService := service.NewOIDCService(oidcServiceCfg, queries)
	err = oidcService.Init()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, middleware := range test.middlewares {
				router.Use(middleware)
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			oidcController := controller.NewOIDCController(controllerCfg, oidcService, group)
			oidcController.SetupRoutes()

			recorder := httptest.NewRecorder()

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		err = db.Close()
		require.NoError(t, err)
	})
}
