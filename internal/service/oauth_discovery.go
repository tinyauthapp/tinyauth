package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
)

// maxDiscoveryBodyBytes caps how much of a discovery document is read, so a slow or hostile issuer
// cannot exhaust memory with an unbounded response body.
const maxDiscoveryBodyBytes = 1 << 20 // 1 MiB

// oidcDiscoveryDocument holds the endpoints Tinyauth can fill from an OIDC provider's well-known
// configuration (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// resolveOIDCDiscovery fills any OAuth endpoint (authorization, token, userinfo) left empty from the
// provider's OIDC discovery document when an issuer is configured. Explicitly configured endpoints are
// never overwritten, so a provider with all endpoints set (or no issuer) is returned unchanged and the
// behaviour stays backwards compatible. It fails soft: on any error the original config is returned with
// the error, so startup continues and the existing "missing endpoint" handling surfaces later.
func resolveOIDCDiscovery(cfg model.OAuthServiceConfig, ctx context.Context) (model.OAuthServiceConfig, error) {
	if cfg.Issuer == "" {
		return cfg, nil
	}

	if cfg.AuthURL != "" && cfg.TokenURL != "" && cfg.UserinfoURL != "" {
		return cfg, nil
	}

	// OIDC discovery requires secure transport (OpenID Connect Discovery 1.0), otherwise an intermediary
	// could swap the discovered endpoints (the token endpoint receives the client secret). A non-HTTPS
	// issuer is only allowed when the operator explicitly sets this provider's insecure flag.
	issuerURL, err := url.Parse(cfg.Issuer)

	if err != nil {
		return cfg, fmt.Errorf("invalid OIDC issuer URL %q: %w", cfg.Issuer, err)
	}

	if issuerURL.Scheme != "https" && !cfg.Insecure {
		return cfg, fmt.Errorf("refusing to fetch OIDC discovery from non-HTTPS issuer %q, set this provider's insecure option to allow it", cfg.Issuer)
	}

	discoveryURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
		},
		// Do not let a redirect downgrade the transport to plaintext (or any non-HTTPS scheme) unless
		// insecure is set; that would reopen the interception window the HTTPS requirement closes.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" && !cfg.Insecure {
				return fmt.Errorf("refusing to follow OIDC discovery redirect to non-HTTPS URL %q", req.URL.Redacted())
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)

	if err != nil {
		return cfg, fmt.Errorf("failed to build OIDC discovery request: %w", err)
	}

	resp, err := client.Do(req)

	if err != nil {
		return cfg, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("OIDC discovery document returned status %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDocument

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryBodyBytes)).Decode(&doc); err != nil {
		return cfg, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	return applyDiscoveryDocument(cfg, doc)
}

// applyDiscoveryDocument validates a fetched discovery document against the configured provider and
// returns the config with any missing endpoint filled in. It enforces the issuer match and the HTTPS
// requirement on discovered endpoints; on any failure it returns the original config unchanged so the
// caller can fail soft.
func applyDiscoveryDocument(cfg model.OAuthServiceConfig, doc oidcDiscoveryDocument) (model.OAuthServiceConfig, error) {
	// The issuer in the document MUST match the configured issuer (OIDC Discovery 1.0 section 4.3,
	// RFC 8414 section 3.3). Rejecting a mismatch prevents a substitution/mix-up attack from pointing
	// the endpoints (the token endpoint receives the client secret) at an unexpected provider. A
	// trailing slash is not significant, so it is ignored.
	if strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(cfg.Issuer, "/") {
		return cfg, fmt.Errorf("OIDC discovery issuer mismatch: document reports %q, expected %q", doc.Issuer, cfg.Issuer)
	}

	// Determine the effective endpoints: an explicitly configured value always wins, otherwise the
	// discovered one is used. A discovered endpoint must be HTTPS unless insecure is set, otherwise a
	// (possibly tampered) document could send the user to a cleartext authorization page or make the
	// client POST its secret to a cleartext token endpoint. Explicitly configured values are the
	// operator's own choice and are left as-is, matching the non-discovery config path. The config is
	// only mutated once every required endpoint is present, so a document that is valid JSON but omits
	// an endpoint is rejected (and surfaces the fail-soft warning) instead of silently building a
	// provider with an empty endpoint.
	secure := func(name, raw string) error {
		if cfg.Insecure || raw == "" {
			return nil
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid %s %q in OIDC discovery document: %w", name, raw, err)
		}
		if parsed.Scheme != "https" {
			return fmt.Errorf("OIDC discovery %s %q is not HTTPS, set this provider's insecure option to allow it", name, raw)
		}
		return nil
	}

	authURL := cfg.AuthURL
	if authURL == "" {
		if err := secure("authorization_endpoint", doc.AuthorizationEndpoint); err != nil {
			return cfg, err
		}
		authURL = doc.AuthorizationEndpoint
	}

	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		if err := secure("token_endpoint", doc.TokenEndpoint); err != nil {
			return cfg, err
		}
		tokenURL = doc.TokenEndpoint
	}

	userinfoURL := cfg.UserinfoURL
	if userinfoURL == "" {
		if err := secure("userinfo_endpoint", doc.UserinfoEndpoint); err != nil {
			return cfg, err
		}
		userinfoURL = doc.UserinfoEndpoint
	}

	var missing []string

	if authURL == "" {
		missing = append(missing, "authorization_endpoint")
	}

	if tokenURL == "" {
		missing = append(missing, "token_endpoint")
	}

	if userinfoURL == "" {
		missing = append(missing, "userinfo_endpoint")
	}

	if len(missing) > 0 {
		return cfg, fmt.Errorf("OIDC discovery document from %q is missing required endpoint(s): %s", cfg.Issuer, strings.Join(missing, ", "))
	}

	cfg.AuthURL = authURL
	cfg.TokenURL = tokenURL
	cfg.UserinfoURL = userinfoURL

	return cfg, nil
}
