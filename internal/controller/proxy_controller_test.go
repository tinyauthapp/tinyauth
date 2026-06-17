package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestProxyController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	const browserUserAgent = `
	Mozilla/5.0 (Linux; Android 8.0.0; SM-G955U Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36`

	simpleCtx := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "testuser",
					Name:     "Testuser",
					Email:    "testuser@example.com",
				},
			},
		})
		c.Next()
	}

	simpleCtxTotp := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "totpuser",
					Name:     "Totpuser",
					Email:    "totpuser@example.com",
				},
			},
		})
		c.Next()
	}

	type testCase struct {
		description string
		middlewares []gin.HandlerFunc
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Should get bad request on invalid proxy",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/invalid", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "Bad request")
			},
		},
		{
			description: "Default forward auth should be detected and used for traefik",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, url.QueryEscape("https://test.example.com/"))
				assert.Contains(t, location, "login_for=app")
				assert.Contains(t, location, "https://tinyauth.example.com/login")
			},
		},
		{
			description: "Auth request (nginx) should be detected and used",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://test.example.com/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				location := recorder.Header().Get("x-tinyauth-location")
				assert.Contains(t, location, url.QueryEscape("https://test.example.com/"))
				assert.Contains(t, location, "login_for=app")
				assert.Contains(t, location, "https://tinyauth.example.com/login")
			},
		},
		{
			description: "Ext authz (envoy) should be detected and used",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil) // test a different method for envoy
				req.Host = "test.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, url.QueryEscape("https://test.example.com/hello"))
				assert.Contains(t, location, "login_for=app")
				assert.Contains(t, location, "https://tinyauth.example.com/login")
			},
		},
		{
			description: "Forward auth with caddy should be detected and used",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/caddy", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, url.QueryEscape("https://test.example.com/"))
				assert.Contains(t, location, "login_for=app")
				assert.Contains(t, location, "https://tinyauth.example.com/login")
			},
		},
		{
			description: "Ensure forward auth fallback for nginx",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				location := recorder.Header().Get("x-tinyauth-location")
				assert.Contains(t, location, url.QueryEscape("https://test.example.com/"))
				assert.Contains(t, location, "login_for=app")
				assert.Contains(t, location, "https://tinyauth.example.com/login")
			},
		},
		{
			description: "Ensure forward auth fallback for envoy",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Host = ""
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/hello")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, url.QueryEscape("https://test.example.com/"))
				assert.Contains(t, location, "login_for=app")
				assert.Contains(t, location, "https://tinyauth.example.com/login")
			},
		},
		{
			description: "Ensure forward auth with non browser returns json for traefik",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), `"status":401`)
				assert.Contains(t, recorder.Body.String(), `"message":"Unauthorized"`)
			},
		},
		{
			description: "Ensure forward auth with non browser returns json for caddy",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/caddy", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), `"status":401`)
				assert.Contains(t, recorder.Body.String(), `"message":"Unauthorized"`)
			},
		},
		{
			description: "Ensure extauthz with envoy non browser returns json",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/hello")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), `"status":401`)
				assert.Contains(t, recorder.Body.String(), `"message":"Unauthorized"`)
			},
		},
		{
			description: "Ensure normal authentication flow for forward auth",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Ensure normal authentication flow for nginx auth request",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://test.example.com/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Ensure normal authentication flow for envoy ext authz",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Host = "test.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Ensure path allow ACL works on forward auth",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "path-allow.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/allowed")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure path allow ACL works on nginx auth request",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://path-allow.example.com/allowed")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure path allow ACL works on envoy ext authz",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/allowed", nil)
				req.Host = "path-allow.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure ip bypass ACL works on forward auth",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ip-bypass.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure ip bypass ACL works on nginx auth request",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://ip-bypass.example.com/")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure ip bypass ACL works on envoy ext authz",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Host = "ip-bypass.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure user allow ACL allows correct user (should allow testuser)",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "user-allow.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			description: "Ensure user allow ACL blocks incorrect user (should block totpuser)",
			middlewares: []gin.HandlerFunc{
				simpleCtxTotp,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "user-allow.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusForbidden, recorder.Code)
				assert.Equal(t, "", recorder.Header().Get("remote-user"))
				assert.Equal(t, "", recorder.Header().Get("remote-name"))
				assert.Equal(t, "", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Test IP block rule, with non browser user agent",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ip-block.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusForbidden, recorder.Code)
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), runtime.AppURL)
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), "ip=10.10.10.10")
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), "ip-block")

			},
		},
		{
			description: "Test IP block rule, with browser user agent",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ip-block.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, url.QueryEscape("10.10.10.10"))
				assert.Contains(t, location, url.QueryEscape("ip-block"))
				assert.Contains(t, location, runtime.AppURL)
			},
		},
		{
			description: "OAuth allowed group",
			middlewares: []gin.HandlerFunc{
				func(ctx *gin.Context) {
					ctx.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderOAuth,
						OAuth: &model.OAuthContext{
							BaseContext: model.BaseContext{
								Username: "testuser",
								Name:     "Testuser",
								Email:    "testuser@example.com",
							},
							Groups: []string{"group1"},
						},
					})
					ctx.Next()
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "oauth-group.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
				assert.Equal(t, "group1", recorder.Header().Get("remote-groups"))
			},
		},
		{
			description: "OAuth not in required groups and non browser",
			middlewares: []gin.HandlerFunc{
				func(ctx *gin.Context) {
					ctx.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderOAuth,
						OAuth: &model.OAuthContext{
							BaseContext: model.BaseContext{
								Username: "testuser",
								Name:     "Testuser",
								Email:    "testuser@example.com",
							},
							Groups: []string{"group3"},
						},
					})
					ctx.Next()
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "oauth-group.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusForbidden, recorder.Code)
				assert.Equal(t, "", recorder.Header().Get("remote-user"))
				assert.Equal(t, "", recorder.Header().Get("remote-name"))
				assert.Equal(t, "", recorder.Header().Get("remote-email"))
				assert.Equal(t, "", recorder.Header().Get("remote-groups"))
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), runtime.AppURL)
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), "groupErr=true")
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), "oauth-group")
			},
		},
		{
			description: "OAuth not in required groups and browser",
			middlewares: []gin.HandlerFunc{
				func(ctx *gin.Context) {
					ctx.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderOAuth,
						OAuth: &model.OAuthContext{
							BaseContext: model.BaseContext{
								Username: "testuser",
								Name:     "Testuser",
								Email:    "testuser@example.com",
							},
							Groups: []string{"group3"},
						},
					})
					ctx.Next()
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "oauth-group.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, "groupErr=true")
				assert.Contains(t, location, "oauth-group")
				assert.Contains(t, location, runtime.AppURL)
			},
		},
		{
			description: "LDAP allowed group",
			middlewares: []gin.HandlerFunc{
				func(ctx *gin.Context) {
					ctx.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderLDAP,
						LDAP: &model.LDAPContext{
							BaseContext: model.BaseContext{
								Username: "testuser",
								Name:     "Testuser",
								Email:    "testuser@example.com",
							},
							Groups: []string{"group1"},
						},
					})
					ctx.Next()
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ldap-group.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
				assert.Equal(t, "group1", recorder.Header().Get("remote-groups"))
			},
		},
		{
			description: "LDAP not in required groups and non browser",
			middlewares: []gin.HandlerFunc{
				func(ctx *gin.Context) {
					ctx.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderLDAP,
						LDAP: &model.LDAPContext{
							BaseContext: model.BaseContext{
								Username: "testuser",
								Name:     "Testuser",
								Email:    "testuser@example.com",
							},
							Groups: []string{"group3"},
						},
					})
					ctx.Next()
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ldap-group.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusForbidden, recorder.Code)
				assert.Equal(t, "", recorder.Header().Get("remote-user"))
				assert.Equal(t, "", recorder.Header().Get("remote-name"))
				assert.Equal(t, "", recorder.Header().Get("remote-email"))
				assert.Equal(t, "", recorder.Header().Get("remote-groups"))
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), runtime.AppURL)
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), "groupErr=true")
				assert.Contains(t, recorder.Header().Get("x-tinyauth-location"), "ldap-group")
			},
		},
		{
			description: "LDAP not in required groups and browser",
			middlewares: []gin.HandlerFunc{
				func(ctx *gin.Context) {
					ctx.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderLDAP,
						LDAP: &model.LDAPContext{
							BaseContext: model.BaseContext{
								Username: "testuser",
								Name:     "Testuser",
								Email:    "testuser@example.com",
							},
							Groups: []string{"group3"},
						},
					})
					ctx.Next()
				},
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ldap-group.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusFound, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Contains(t, location, "groupErr=true")
				assert.Contains(t, location, "ldap-group")
				assert.Contains(t, location, runtime.AppURL)
			},
		},
		{
			description: "Should add basic auth if it's in ACLs",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "basic-auth.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("authorization", "foo") // should be overridden by basic auth
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				authorizationHeader := recorder.Header().Get("Authorization")
				assert.NotEmpty(t, authorizationHeader)
				assert.Equal(t, fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("test:password"))), authorizationHeader)
			},
		},
		{
			description: "Authorization header should be preserved when not basic auth acls",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("authorization", "Bearer mytoken")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				authorizationHeader := recorder.Header().Get("Authorization")
				assert.NotEmpty(t, authorizationHeader)
				assert.Equal(t, "Bearer mytoken", authorizationHeader)
			},
		},
		{
			description: "Should add response headers if present",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "response-headers.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Equal(t, "bar", recorder.Header().Get("x-foo"))
			},
		},
	}

	store := memory.New()

	ctx := context.TODO()
	dg := ding.New(ctx)

	broker := service.NewOAuthBrokerService(service.OAuthBrokerServiceInput{
		Log:     log,
		Runtime: &runtime,
		Ctx:     ctx,
	})
	aclsService := service.NewAccessControlsService(service.AccessControlServiceInput{
		Log:           log,
		Config:        &cfg,
		LabelProvider: nil,
	})

	policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	require.NoError(t, err)

	policyEngine.RegisterRule(service.RuleUserAllowed, &service.UserAllowedRule{
		Log: log,
	})
	policyEngine.RegisterRule(service.RuleOAuthGroup, &service.OAuthGroupRule{
		Log: log,
	})
	policyEngine.RegisterRule(service.RuleLDAPGroup, &service.LDAPGroupRule{
		Log: log,
	})
	policyEngine.RegisterRule(service.RuleAuthEnabled, &service.AuthEnabledRule{
		Log: log,
	})
	policyEngine.RegisterRule(service.RuleIPAllowed, &service.IPAllowedRule{
		Log:    log,
		Config: cfg,
	})
	policyEngine.RegisterRule(service.RuleIPBypassed, &service.IPBypassedRule{
		Log: log,
	})

	authService := service.NewAuthService(service.AuthServiceInput{
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

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, m := range test.middlewares {
				router.Use(m)
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			NewProxyController(ProxyControllerInput{
				Log:           log,
				RuntimeConfig: &runtime,
				RouterGroup:   group,
				ACLsService:   aclsService,
				AuthService:   authService,
				PolicyEngine:  policyEngine,
			})

			test.run(t, router, recorder)
		})
	}
}
