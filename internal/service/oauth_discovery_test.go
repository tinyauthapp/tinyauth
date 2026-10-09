package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

// discoveryTestServer serves a discovery document at the well-known path. docFn receives the server's
// own URL so a document can advertise a matching (or deliberately mismatched) issuer. The server speaks
// plain HTTP, so tests that expect discovery to proceed set the provider's Insecure flag.
func discoveryTestServer(t *testing.T, status int, docFn func(issuer string) string) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(docFn(server.URL)))
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func validDoc(issuer string) string {
	return `{
		"issuer": "` + issuer + `",
		"authorization_endpoint": "https://idp.example.com/authorize",
		"token_endpoint": "https://idp.example.com/token",
		"userinfo_endpoint": "https://idp.example.com/userinfo"
	}`
}

func TestResolveOIDCDiscovery(t *testing.T) {
	t.Run("no issuer is returned unchanged", func(t *testing.T) {
		cfg := model.OAuthServiceConfig{ClientID: "abc"}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, cfg, got)
	})

	t.Run("fills missing endpoints from the discovery document", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, validDoc)

		cfg := model.OAuthServiceConfig{Issuer: server.URL, Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/authorize", got.AuthURL)
		assert.Equal(t, "https://idp.example.com/token", got.TokenURL)
		assert.Equal(t, "https://idp.example.com/userinfo", got.UserinfoURL)
	})

	t.Run("accepts an issuer that differs only by a trailing slash", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, validDoc)

		cfg := model.OAuthServiceConfig{Issuer: server.URL + "/", Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/authorize", got.AuthURL)
	})

	t.Run("does not overwrite explicitly configured endpoints", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, validDoc)

		cfg := model.OAuthServiceConfig{
			Issuer:   server.URL,
			Insecure: true,
			AuthURL:  "https://custom.example.com/auth",
			TokenURL: "https://custom.example.com/token",
			// UserinfoURL is left empty, so only it should be filled
		}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, "https://custom.example.com/auth", got.AuthURL)
		assert.Equal(t, "https://custom.example.com/token", got.TokenURL)
		assert.Equal(t, "https://idp.example.com/userinfo", got.UserinfoURL)
	})

	t.Run("rejects a non-HTTPS issuer unless insecure is set", func(t *testing.T) {
		// The server would answer, but discovery must refuse the cleartext issuer before fetching.
		server := discoveryTestServer(t, http.StatusOK, validDoc)

		cfg := model.OAuthServiceConfig{Issuer: server.URL} // http://, Insecure defaults to false

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-HTTPS")
		assert.Empty(t, got.AuthURL)
		assert.Empty(t, got.TokenURL)
		assert.Empty(t, got.UserinfoURL)
	})

	t.Run("rejects a document whose issuer does not match", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, func(issuer string) string {
			return `{
				"issuer": "https://evil.example.com",
				"authorization_endpoint": "https://evil.example.com/authorize",
				"token_endpoint": "https://evil.example.com/token",
				"userinfo_endpoint": "https://evil.example.com/userinfo"
			}`
		})

		cfg := model.OAuthServiceConfig{Issuer: server.URL, Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer mismatch")
		assert.Empty(t, got.AuthURL)
		assert.Empty(t, got.TokenURL)
		assert.Empty(t, got.UserinfoURL)
	})

	t.Run("rejects a document that omits a required endpoint", func(t *testing.T) {
		// Valid JSON and a matching issuer, but no token_endpoint: this must error (and surface the
		// fail-soft warning) rather than silently building a provider with an empty token endpoint.
		server := discoveryTestServer(t, http.StatusOK, func(issuer string) string {
			return `{
				"issuer": "` + issuer + `",
				"authorization_endpoint": "https://idp.example.com/authorize",
				"userinfo_endpoint": "https://idp.example.com/userinfo"
			}`
		})

		cfg := model.OAuthServiceConfig{Issuer: server.URL, Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "token_endpoint")
		assert.Empty(t, got.AuthURL)
		assert.Empty(t, got.TokenURL)
		assert.Empty(t, got.UserinfoURL)
	})

	t.Run("uses an explicit endpoint to satisfy one the document omits", func(t *testing.T) {
		// The document omits token_endpoint, but it is configured explicitly, so discovery still succeeds.
		server := discoveryTestServer(t, http.StatusOK, func(issuer string) string {
			return `{
				"issuer": "` + issuer + `",
				"authorization_endpoint": "https://idp.example.com/authorize",
				"userinfo_endpoint": "https://idp.example.com/userinfo"
			}`
		})

		cfg := model.OAuthServiceConfig{
			Issuer:   server.URL,
			Insecure: true,
			TokenURL: "https://custom.example.com/token",
		}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/authorize", got.AuthURL)
		assert.Equal(t, "https://custom.example.com/token", got.TokenURL)
		assert.Equal(t, "https://idp.example.com/userinfo", got.UserinfoURL)
	})

	t.Run("skips discovery when all endpoints are already set", func(t *testing.T) {
		// The issuer points at a server that always errors; discovery must not be attempted.
		server := discoveryTestServer(t, http.StatusInternalServerError, func(issuer string) string {
			return "boom"
		})

		cfg := model.OAuthServiceConfig{
			Issuer:      server.URL,
			AuthURL:     "https://custom.example.com/auth",
			TokenURL:    "https://custom.example.com/token",
			UserinfoURL: "https://custom.example.com/userinfo",
		}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, cfg, got)
	})

	t.Run("fails soft on a non-200 response", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusNotFound, func(issuer string) string {
			return "not found"
		})

		cfg := model.OAuthServiceConfig{Issuer: server.URL, Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Empty(t, got.AuthURL)
		assert.Empty(t, got.TokenURL)
		assert.Empty(t, got.UserinfoURL)
	})

	t.Run("fails soft on an invalid document", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, func(issuer string) string {
			return "not json"
		})

		cfg := model.OAuthServiceConfig{Issuer: server.URL, Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Empty(t, got.AuthURL)
	})

	t.Run("rejects a cleartext discovered authorization endpoint when not insecure", func(t *testing.T) {
		doc := oidcDiscoveryDocument{
			Issuer:                "https://idp.example.com",
			AuthorizationEndpoint: "http://idp.example.com/authorize", // cleartext
			TokenEndpoint:         "https://idp.example.com/token",
			UserinfoEndpoint:      "https://idp.example.com/userinfo",
		}

		got, err := applyDiscoveryDocument(model.OAuthServiceConfig{Issuer: "https://idp.example.com"}, doc)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization_endpoint")
		assert.Contains(t, err.Error(), "not HTTPS")
		assert.Empty(t, got.AuthURL)
	})

	t.Run("rejects a cleartext discovered token endpoint when not insecure", func(t *testing.T) {
		doc := oidcDiscoveryDocument{
			Issuer:                "https://idp.example.com",
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "http://idp.example.com/token", // cleartext, would leak the client secret
			UserinfoEndpoint:      "https://idp.example.com/userinfo",
		}

		got, err := applyDiscoveryDocument(model.OAuthServiceConfig{Issuer: "https://idp.example.com"}, doc)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "token_endpoint")
		assert.Empty(t, got.TokenURL)
	})

	t.Run("allows a cleartext discovered endpoint when insecure is set", func(t *testing.T) {
		doc := oidcDiscoveryDocument{
			Issuer:                "http://idp.example.com",
			AuthorizationEndpoint: "http://idp.example.com/authorize",
			TokenEndpoint:         "http://idp.example.com/token",
			UserinfoEndpoint:      "http://idp.example.com/userinfo",
		}

		got, err := applyDiscoveryDocument(model.OAuthServiceConfig{Issuer: "http://idp.example.com", Insecure: true}, doc)

		require.NoError(t, err)
		assert.Equal(t, "http://idp.example.com/authorize", got.AuthURL)
		assert.Equal(t, "http://idp.example.com/token", got.TokenURL)
	})

	t.Run("fails soft on an oversized body instead of exhausting memory", func(t *testing.T) {
		// Pad the document past the read cap so the body cannot be fully consumed; the truncated
		// read must surface as a decode error rather than an unbounded allocation.
		padding := strings.Repeat(" ", (2<<20)+1)
		server := discoveryTestServer(t, http.StatusOK, func(issuer string) string {
			return `{"issuer": "` + issuer + `", "authorization_endpoint": "https://idp.example.com/authorize"` + padding + `}`
		})

		cfg := model.OAuthServiceConfig{Issuer: server.URL, Insecure: true}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Empty(t, got.AuthURL)
	})
}
