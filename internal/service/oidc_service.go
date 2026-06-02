package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

var (
	SupportedScopes        = []string{"openid", "profile", "email", "phone", "address", "groups"}
	SupportedResponseTypes = []string{"code"}
	SupportedGrantTypes    = []string{"authorization_code", "refresh_token"}
)

var (
	ErrCodeExpired   = errors.New("code_expired")
	ErrCodeNotFound  = errors.New("code_not_found")
	ErrTokenNotFound = errors.New("token_not_found")
	ErrTokenExpired  = errors.New("token_expired")
	ErrInvalidClient = errors.New("invalid_client")
)

// This is not spec-compliant, the ID token SHOULD NOT contain user info claims but,
// it has became a "standard" and apps are looking for the claims in the ID tokens
// instead of calling the userinfo endpoint, so we include them in the ID token as well
// for better compatibility with existing apps
type ClaimSet struct {
	Iss               string   `json:"iss"`
	Aud               string   `json:"aud"`
	Sub               string   `json:"sub"`
	Iat               int64    `json:"iat"`
	Exp               int64    `json:"exp"`
	Name              string   `json:"name,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	MiddleName        string   `json:"middle_name,omitempty"`
	Nickname          string   `json:"nickname,omitempty"`
	Profile           string   `json:"profile,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Website           string   `json:"website,omitempty"`
	Gender            string   `json:"gender,omitempty"`
	Birthdate         string   `json:"birthdate,omitempty"`
	Zoneinfo          string   `json:"zoneinfo,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
}

// We use this struct as both a response struct and a struct to store userinfo
// in the database
type UserinfoResponse struct {
	Sub                 string              `json:"sub"`
	Name                string              `json:"name,omitempty"`
	GivenName           string              `json:"given_name,omitempty"`
	FamilyName          string              `json:"family_name,omitempty"`
	MiddleName          string              `json:"middle_name,omitempty"`
	Nickname            string              `json:"nickname,omitempty"`
	Profile             string              `json:"profile,omitempty"`
	Picture             string              `json:"picture,omitempty"`
	Website             string              `json:"website,omitempty"`
	Gender              string              `json:"gender,omitempty"`
	Birthdate           string              `json:"birthdate,omitempty"`
	Zoneinfo            string              `json:"zoneinfo,omitempty"`
	Locale              string              `json:"locale,omitempty"`
	Email               string              `json:"email,omitempty"`
	PreferredUsername   string              `json:"preferred_username,omitempty"`
	Groups              []string            `json:"groups,omitempty"`
	EmailVerified       bool                `json:"email_verified,omitempty"`
	PhoneNumber         string              `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool               `json:"phone_number_verified,omitempty"`
	Address             *model.AddressClaim `json:"address,omitempty"`
	UpdatedAt           int64               `json:"updated_at"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type AuthorizeRequest struct {
	Scope               string `json:"scope" binding:"required"`
	ResponseType        string `json:"response_type" binding:"required"`
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type AuthorizeCodeEntry struct {
	CodeHash      string
	Scope         string
	RedirectURI   string
	ClientID      string
	Nonce         string
	CodeChallenge string
	Userinfo      UserinfoResponse
}

type UsedCodeEntry struct {
	Sub string
}

type OIDCService struct {
	log     *logger.Logger
	config  model.Config
	runtime model.RuntimeConfig
	queries repository.Store

	clients    map[string]model.OIDCClientConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string

	caches struct {
		code     *CacheStore[AuthorizeCodeEntry]
		usedCode *CacheStore[UsedCodeEntry]
	}
}

func NewOIDCService(
	log *logger.Logger,
	config model.Config,
	runtime model.RuntimeConfig,
	queries repository.Store,
	dg *ding.Ding) (*OIDCService, error) {
	// If not configured, skip init
	if len(runtime.OIDCClients) == 0 {
		return nil, nil
	}

	// Ensure issuer is https
	uissuer, err := url.Parse(runtime.AppURL)

	if err != nil {
		return nil, fmt.Errorf("failed to parse app url: %w", err)
	}

	if uissuer.Scheme != "https" {
		return nil, errors.New("issuer must be https")
	}

	issuer := fmt.Sprintf("%s://%s", uissuer.Scheme, uissuer.Host)

	// Create/load private and public keys
	if strings.TrimSpace(config.OIDC.PrivateKeyPath) == "" ||
		strings.TrimSpace(config.OIDC.PublicKeyPath) == "" {
		return nil, errors.New("private key path and public key path are required")
	}

	var privateKey *rsa.PrivateKey

	fprivateKey, err := os.ReadFile(config.OIDC.PrivateKeyPath)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if errors.Is(err, os.ErrNotExist) {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(privateKey)
		if der == nil {
			return nil, errors.New("failed to marshal private key")
		}
		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		log.App.Trace().Str("type", "RSA PRIVATE KEY").Msg("Generated private RSA key")
		err = os.WriteFile(config.OIDC.PrivateKeyPath, encoded, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to write private key to file: %w", err)
		}
	} else {
		block, _ := pem.Decode(fprivateKey)
		if block == nil {
			return nil, errors.New("failed to decode private key")
		}
		log.App.Trace().Str("type", block.Type).Msg("Loaded private key")
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	var publicKey crypto.PublicKey

	fpublicKey, err := os.ReadFile(config.OIDC.PublicKeyPath)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	if errors.Is(err, os.ErrNotExist) {
		publicKey = privateKey.Public()
		der := x509.MarshalPKCS1PublicKey(publicKey.(*rsa.PublicKey))
		if der == nil {
			return nil, errors.New("failed to marshal public key")
		}
		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: der,
		})
		log.App.Trace().Str("type", "RSA PUBLIC KEY").Msg("Generated public RSA key")
		err = os.WriteFile(config.OIDC.PublicKeyPath, encoded, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		block, _ := pem.Decode(fpublicKey)
		if block == nil {
			return nil, errors.New("failed to decode public key")
		}
		log.App.Trace().Str("type", block.Type).Msg("Loaded public key")
		switch block.Type {
		case "RSA PUBLIC KEY":
			publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		case "PUBLIC KEY":
			publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
		}
	}

	rPublicKey, ok := publicKey.(*rsa.PublicKey)

	if !ok {
		return nil, fmt.Errorf("public key is not an rsa public key")
	}

	if rPublicKey.N.Cmp(privateKey.N) != 0 || rPublicKey.E != privateKey.E {
		return nil, fmt.Errorf("public key does not pair with private key")
	}

	// We will reorganize the client into a map with the client ID as the key
	clients := make(map[string]model.OIDCClientConfig)

	for id, client := range config.OIDC.Clients {
		client.ID = id
		if client.Name == "" {
			client.Name = utils.Capitalize(client.ID)
		}
		clients[client.ClientID] = client
	}

	// Load the client secrets from files if they exist
	for id, client := range clients {
		secret := utils.GetSecret(client.ClientSecret, client.ClientSecretFile)
		if secret != "" {
			client.ClientSecret = secret
		}
		client.ClientSecretFile = ""
		clients[id] = client
		log.App.Debug().Str("clientId", client.ClientID).Msg("Loaded OIDC client configuration")
	}

	// Initialize the service
	service := &OIDCService{
		log:     log,
		config:  config,
		runtime: runtime,
		queries: queries,

		clients:    clients,
		privateKey: privateKey,
		publicKey:  rPublicKey,
		issuer:     issuer,
	}

	// Start cleanup routine
	dg.Go(service.cleanupRoutine, ding.RingMinor)

	// Create caches
	codeCash := NewCacheStore[AuthorizeCodeEntry](256)
	usedCode := NewCacheStore[UsedCodeEntry](256)
	service.caches.code = codeCash
	service.caches.usedCode = usedCode

	// Start cache cleanup routine
	dg.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.caches.code.Sweep()
				service.caches.usedCode.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

	return service, nil
}

func (service *OIDCService) GetIssuer() string {
	return service.issuer
}

func (service *OIDCService) GetClient(id string) (model.OIDCClientConfig, bool) {
	client, ok := service.clients[id]
	return client, ok
}

func (service *OIDCService) ValidateAuthorizeParams(req AuthorizeRequest) error {
	// Validate client ID
	client, ok := service.GetClient(req.ClientID)
	if !ok {
		return errors.New("access_denied")
	}

	// Redirect URI to verify that it's trusted
	if !slices.Contains(client.TrustedRedirectURIs, req.RedirectURI) {
		return errors.New("invalid_request_uri")
	}

	// Scopes
	scopes := strings.Split(req.Scope, " ")

	if len(scopes) == 0 || strings.TrimSpace(req.Scope) == "" {
		return errors.New("invalid_scope")
	}

	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" {
			return errors.New("invalid_scope")
		}
		if !slices.Contains(SupportedScopes, scope) {
			service.log.App.Warn().Str("scope", scope).Msg("Requested unsupported scope")
		}
	}

	// Response type
	if !slices.Contains(SupportedResponseTypes, req.ResponseType) {
		return errors.New("unsupported_response_type")
	}

	// PKCE code challenge method if set
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" {
		if req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
			return errors.New("invalid_request")
		}
	}

	return nil
}

func (service *OIDCService) filterScopes(scopes []string) []string {
	return utils.Filter(scopes, func(scope string) bool {
		return slices.Contains(SupportedScopes, scope)
	})
}

func (service *OIDCService) CreateCode(req AuthorizeRequest, userContext model.UserContext) string {
	code := utils.GenerateString(32)
	sub := service.CreateSub(userContext, req.ClientID)

	entry := AuthorizeCodeEntry{
		CodeHash:    service.Hash(code),
		Scope:       strings.Join(service.filterScopes(strings.Split(req.Scope, " ")), " "),
		RedirectURI: req.RedirectURI,
		ClientID:    req.ClientID,
		Nonce:       req.Nonce,
		Userinfo:    service.userinfoFromContext(userContext, sub),
	}

	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "S256" {
			entry.CodeChallenge = req.CodeChallenge
		} else {
			entry.CodeChallenge = service.hashAndEncodePKCE(req.CodeChallenge)
			service.log.App.Warn().Msg("Using plain PKCE code challenge method is not recommended, consider switching to S256 for better security")
		}
	}

	// Store the code in the cache
	service.caches.code.Set(entry.CodeHash, entry, 1*time.Minute)

	return code
}

func (service *OIDCService) userinfoFromContext(userContext model.UserContext, sub string) UserinfoResponse {
	userInfo := UserinfoResponse{
		Sub:               sub,
		Name:              userContext.GetName(),
		Email:             userContext.GetEmail(),
		PreferredUsername: userContext.GetUsername(),
		UpdatedAt:         time.Now().Unix(),
	}

	if userContext.IsLocal() {
		userInfo.GivenName = userContext.Local.Attributes.GivenName
		userInfo.FamilyName = userContext.Local.Attributes.FamilyName
		userInfo.MiddleName = userContext.Local.Attributes.MiddleName
		userInfo.Nickname = userContext.Local.Attributes.Nickname
		userInfo.Profile = userContext.Local.Attributes.Profile
		userInfo.Picture = userContext.Local.Attributes.Picture
		userInfo.Website = userContext.Local.Attributes.Website
		userInfo.Gender = userContext.Local.Attributes.Gender
		userInfo.Birthdate = userContext.Local.Attributes.Birthdate
		userInfo.Zoneinfo = userContext.Local.Attributes.Zoneinfo
		userInfo.Locale = userContext.Local.Attributes.Locale
		userInfo.PhoneNumber = userContext.Local.Attributes.PhoneNumber
		userInfo.Address = &userContext.Local.Attributes.Address
	}

	// Tinyauth will pass through the groups it got from an LDAP or an OIDC server
	if userContext.IsLDAP() {
		userInfo.Groups = userContext.LDAP.Groups
	}

	if userContext.IsOAuth() {
		userInfo.Groups = userContext.OAuth.Groups
	}

	return userInfo
}

func (service *OIDCService) ValidateGrantType(grantType string) error {
	if !slices.Contains(SupportedGrantTypes, grantType) {
		return errors.New("unsupported_grant_type")
	}

	return nil
}

func (service *OIDCService) GetCodeEntry(codeHash string, clientId string) (*AuthorizeCodeEntry, bool) {
	var entry AuthorizeCodeEntry
	var ok bool

	service.caches.code.WithLock(func(actions CacheStoreActions[AuthorizeCodeEntry]) {
		entry, ok = service.caches.code.Get(codeHash)

		if !ok {
			return
		}

		if entry.ClientID != clientId {
			ok = false
			return
		}

		// Since the code can only be used once, we delete it from the cache after retrieving it
		service.caches.code.Delete(codeHash)
	})

	if !ok {
		return nil, false
	}

	return &entry, true
}

func (service *OIDCService) generateIDToken(client model.OIDCClientConfig, user UserinfoResponse, scope string, nonce string) (string, error) {
	createdAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Duration(service.config.Auth.SessionExpiry) * time.Second).Unix()

	hasher := sha256.New()

	der := x509.MarshalPKCS1PublicKey(service.publicKey)

	if der == nil {
		return "", errors.New("failed to marshal public key")
	}

	hasher.Write(der)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       service.privateKey,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": "jwt",
			"jku": fmt.Sprintf("%s/.well-known/jwks.json", service.issuer),
			"kid": base64.URLEncoding.EncodeToString(hasher.Sum(nil)),
		},
	})

	if err != nil {
		return "", err
	}

	userInfo := service.CompileUserinfo(user, scope)

	claims := ClaimSet{
		Iss:               service.issuer,
		Aud:               client.ClientID,
		Sub:               user.Sub,
		Iat:               createdAt,
		Exp:               expiresAt,
		Name:              userInfo.Name,
		Email:             userInfo.Email,
		EmailVerified:     userInfo.EmailVerified,
		PreferredUsername: userInfo.PreferredUsername,
		Groups:            userInfo.Groups,
		Nonce:             nonce,
	}

	payload, err := json.Marshal(claims)

	if err != nil {
		return "", err
	}

	object, err := signer.Sign(payload)

	if err != nil {
		return "", err
	}

	token, err := object.CompactSerialize()

	if err != nil {
		return "", err
	}

	return token, nil
}

func (service *OIDCService) GenerateAccessToken(ctx context.Context, client model.OIDCClientConfig, codeEntry AuthorizeCodeEntry) (*TokenResponse, error) {
	idToken, err := service.generateIDToken(client, codeEntry.Userinfo, codeEntry.Scope, codeEntry.Nonce)

	if err != nil {
		return nil, err
	}

	accessToken := utils.GenerateString(32)
	refreshToken := utils.GenerateString(32)

	tokenExpiresAt := time.Now().Add(time.Duration(service.config.Auth.SessionExpiry) * time.Second).Unix()

	// Refresh token lives double the time of an access token but can't be used to access userinfo
	refreshTokenExpiresAt := time.Now().Add(time.Duration(service.config.Auth.SessionExpiry*2) * time.Second).Unix()

	tokenResponse := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(service.config.Auth.SessionExpiry),
		IDToken:      idToken,
		Scope:        strings.ReplaceAll(codeEntry.Scope, ",", " "),
	}

	var userInfoJson []byte

	userInfoJson, err = json.Marshal(codeEntry.Userinfo)

	if err != nil {
		return nil, err
	}

	_, err = service.queries.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
		Sub:                   codeEntry.Userinfo.Sub,
		AccessTokenHash:       service.Hash(accessToken),
		RefreshTokenHash:      service.Hash(refreshToken),
		Scope:                 codeEntry.Scope,
		ClientID:              client.ClientID,
		TokenExpiresAt:        tokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		Nonce:                 codeEntry.Nonce,
		UserinfoJson:          string(userInfoJson),
	})

	if err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (service *OIDCService) RefreshAccessToken(ctx context.Context, refreshToken string, clientId string) (*TokenResponse, error) {
	entry, err := service.queries.GetOIDCSessionByRefreshTokenHash(ctx, service.Hash(refreshToken))

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	if entry.RefreshTokenExpiresAt < time.Now().Unix() {
		return nil, ErrTokenExpired
	}

	// Ensure the client ID in the request matches the client ID in the token
	if entry.ClientID != clientId {
		return nil, ErrInvalidClient
	}

	// we need to unmarshal the userinfo from the database to include it in the new ID token,
	// since the ID token includes user claims for better compatibility with existing apps
	var userInfo UserinfoResponse

	err = json.Unmarshal([]byte(entry.UserinfoJson), &userInfo)

	if err != nil {
		return nil, err
	}

	idToken, err := service.generateIDToken(model.OIDCClientConfig{
		ClientID: entry.ClientID,
	}, userInfo, entry.Scope, entry.Nonce)

	if err != nil {
		return nil, err
	}

	accessToken := utils.GenerateString(32)
	newRefreshToken := utils.GenerateString(32)

	tokenExpiresAt := time.Now().Add(time.Duration(service.config.Auth.SessionExpiry) * time.Second).Unix()
	refreshTokenExpiresAt := time.Now().Add(time.Duration(service.config.Auth.SessionExpiry*2) * time.Second).Unix()

	tokenResponse := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(service.config.Auth.SessionExpiry),
		IDToken:      idToken,
		Scope:        strings.ReplaceAll(entry.Scope, ",", " "),
	}

	_, err = service.queries.UpdateOIDCSession(ctx, repository.UpdateOIDCSessionParams{
		Sub:                   entry.Sub,
		AccessTokenHash:       service.Hash(accessToken),
		RefreshTokenHash:      service.Hash(newRefreshToken),
		Scope:                 entry.Scope,
		ClientID:              entry.ClientID,
		TokenExpiresAt:        tokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		Nonce:                 entry.Nonce,
		UserinfoJson:          entry.UserinfoJson,
	})

	if err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (service *OIDCService) GetSessionByToken(ctx context.Context, tokenHash string) (*repository.OidcSession, error) {
	entry, err := service.queries.GetOIDCSessionByAccessTokenHash(ctx, tokenHash)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	if entry.TokenExpiresAt < time.Now().Unix() {
		// If refresh token is expired, delete the session
		// since there is no way for the client to access anything anymore
		if entry.RefreshTokenExpiresAt < time.Now().Unix() {
			// Deletes by sub
			err := service.queries.DeleteOIDCSessionBySub(ctx, entry.Sub)
			if err != nil {
				return nil, err
			}
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenExpired
	}

	return &entry, nil
}

func (service *OIDCService) CompileUserinfo(user UserinfoResponse, scope string) UserinfoResponse {
	scopes := strings.Split(scope, " ")
	userInfo := UserinfoResponse{
		Sub:       user.Sub,
		UpdatedAt: user.UpdatedAt,
	}

	if slices.Contains(scopes, "profile") {
		userInfo.Name = user.Name
		userInfo.PreferredUsername = user.PreferredUsername
		userInfo.GivenName = user.GivenName
		userInfo.FamilyName = user.FamilyName
		userInfo.MiddleName = user.MiddleName
		userInfo.Nickname = user.Nickname
		userInfo.Profile = user.Profile
		userInfo.Picture = user.Picture
		userInfo.Website = user.Website
		userInfo.Gender = user.Gender
		userInfo.Birthdate = user.Birthdate
		userInfo.Zoneinfo = user.Zoneinfo
		userInfo.Locale = user.Locale
	}

	if slices.Contains(scopes, "email") {
		userInfo.Email = user.Email
		userInfo.EmailVerified = user.Email != ""
	}

	if slices.Contains(scopes, "groups") {
		userInfo.Groups = user.Groups
	}

	if slices.Contains(scopes, "phone") {
		userInfo.PhoneNumber = user.PhoneNumber
		verified := user.PhoneNumber != ""
		userInfo.PhoneNumberVerified = &verified
	}

	if slices.Contains(scopes, "address") {
		userInfo.Address = user.Address
	}

	return userInfo
}

func (service *OIDCService) Hash(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (service *OIDCService) DeleteOldSession(ctx context.Context, sub string) error {
	err := service.queries.DeleteOIDCSessionBySub(ctx, sub)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	return nil
}

func (service *OIDCService) cleanupRoutine(ctx context.Context) {
	service.log.App.Debug().Msg("Starting OIDC cleanup routine")
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			service.log.App.Debug().Msg("Performing OIDC cleanup routine")

			currentTime := time.Now().Unix()

			// Limitation of sqlc, meaning we need to specify a timestamp for both token and refresh token expiry
			err := service.queries.DeleteExpiredOIDCSessions(ctx, repository.DeleteExpiredOIDCSessionsParams{
				TokenExpiresAt:        currentTime,
				RefreshTokenExpiresAt: currentTime,
			})

			if err != nil {
				service.log.App.Warn().Err(err).Msg("Failed to delete expired OIDC sessions")
			}

			service.log.App.Debug().Msg("Finished OIDC cleanup routine")
		case <-ctx.Done():
			service.log.App.Debug().Msg("Stopping OIDC cleanup routine")
			return
		}
	}
}

func (service *OIDCService) GetJWK() ([]byte, error) {
	hasher := sha256.New()

	der := x509.MarshalPKCS1PublicKey(service.publicKey)

	if der == nil {
		return nil, errors.New("failed to marshal public key")
	}

	hasher.Write(der)

	jwk := jose.JSONWebKey{
		Key:       service.publicKey,
		Algorithm: string(jose.RS256),
		Use:       "sig",
		KeyID:     base64.URLEncoding.EncodeToString(hasher.Sum(nil)),
	}

	return jwk.MarshalJSON()
}

func (service *OIDCService) ValidatePKCE(codeChallenge string, codeVerifier string) bool {
	if codeChallenge == "" {
		return true
	}
	return codeChallenge == service.hashAndEncodePKCE(codeVerifier)
}

func (service *OIDCService) hashAndEncodePKCE(codeVerifier string) string {
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

// WARNING: Since Tinyauth is stateless, we cannot have a sub that never changes.
// We will just create a uuid out of the username and client name which remains stable,
// but if username or client name changes then sub changes too.
func (service *OIDCService) CreateSub(userContext model.UserContext, clientId string) string {
	return utils.GenerateUUID(fmt.Sprintf("%s:%s", userContext.GetUsername(), clientId))
}

func (service *OIDCService) IsCodeUsed(codeHash string) (string, bool) {
	entry, ok := service.caches.usedCode.Get(codeHash)

	if !ok {
		return "", false
	}

	return entry.Sub, true
}

func (service *OIDCService) MarkCodeAsUsed(codeHash string, sub string) {
	entry := UsedCodeEntry{
		Sub: sub,
	}
	service.caches.usedCode.Set(codeHash, entry, 2*time.Minute)
}

func (service *OIDCService) DeleteSessionBySub(ctx context.Context, sub string) error {
	return service.queries.DeleteOIDCSessionBySub(ctx, sub)
}
