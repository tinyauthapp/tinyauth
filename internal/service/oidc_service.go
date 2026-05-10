package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"slices"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
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

type OIDCService struct {
	log     *logger.Logger
	config  model.Config
	runtime model.RuntimeConfig
	queries *repository.Queries
	context context.Context

	clients    map[string]model.OIDCClientConfig
	privateKey *rsa.PrivateKey
	publicKey  crypto.PublicKey
	issuer     string
}

func NewOIDCService(
	log *logger.Logger,
	config model.Config,
	runtime model.RuntimeConfig,
	queries *repository.Queries,
	ctx context.Context,
	wg *sync.WaitGroup) (*OIDCService, error) {
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
		context: ctx,

		clients:    clients,
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
	}

	// Start cleanup routine
	wg.Go(service.cleanupRoutine)

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

	// Redirect URI
	if !slices.Contains(client.TrustedRedirectURIs, req.RedirectURI) {
		return errors.New("invalid_request_uri")
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

func (service *OIDCService) StoreCode(c *gin.Context, sub string, code string, req AuthorizeRequest) error {
	// Fixed 10 minutes
	expiresAt := time.Now().Add(time.Minute * time.Duration(10)).Unix()

	entry := repository.CreateOidcCodeParams{
		Sub:      sub,
		CodeHash: service.Hash(code),
		// Here it's safe to split and trust the output since, we validated the scopes before
		Scope:       strings.Join(service.filterScopes(strings.Split(req.Scope, " ")), ","),
		RedirectURI: req.RedirectURI,
		ClientID:    req.ClientID,
		ExpiresAt:   expiresAt,
		Nonce:       req.Nonce,
	}

	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "S256" {
			entry.CodeChallenge = req.CodeChallenge
		} else {
			entry.CodeChallenge = service.hashAndEncodePKCE(req.CodeChallenge)
			service.log.App.Warn().Msg("Using plain PKCE code challenge method is not recommended, consider switching to S256 for better security")
		}
	}

	// Insert the code into the database
	_, err := service.queries.CreateOidcCode(c, entry)

	return err
}

func (service *OIDCService) StoreUserinfo(c *gin.Context, sub string, userContext model.UserContext, req AuthorizeRequest) error {
	userInfoParams := repository.CreateOidcUserInfoParams{
		Sub:               sub,
		Name:              userContext.GetName(),
		Email:             userContext.GetEmail(),
		PreferredUsername: userContext.GetUsername(),
		UpdatedAt:         time.Now().Unix(),
	}

	if userContext.IsLocal() {
		addressJSON, err := json.Marshal(userContext.Local.Attributes.Address)
		if err != nil {
			return err
		}
		userInfoParams.GivenName = userContext.Local.Attributes.GivenName
		userInfoParams.FamilyName = userContext.Local.Attributes.FamilyName
		userInfoParams.MiddleName = userContext.Local.Attributes.MiddleName
		userInfoParams.Nickname = userContext.Local.Attributes.Nickname
		userInfoParams.Profile = userContext.Local.Attributes.Profile
		userInfoParams.Picture = userContext.Local.Attributes.Picture
		userInfoParams.Website = userContext.Local.Attributes.Website
		userInfoParams.Gender = userContext.Local.Attributes.Gender
		userInfoParams.Birthdate = userContext.Local.Attributes.Birthdate
		userInfoParams.Zoneinfo = userContext.Local.Attributes.Zoneinfo
		userInfoParams.Locale = userContext.Local.Attributes.Locale
		userInfoParams.PhoneNumber = userContext.Local.Attributes.PhoneNumber
		userInfoParams.Address = string(addressJSON)
	}

	// Tinyauth will pass through the groups it got from an LDAP or an OIDC server
	if userContext.IsLDAP() {
		userInfoParams.Groups = strings.Join(userContext.LDAP.Groups, ",")
	}

	if userContext.IsOAuth() {
		userInfoParams.Groups = strings.Join(userContext.OAuth.Groups, ",")
	}

	_, err := service.queries.CreateOidcUserInfo(c, userInfoParams)

	return err
}

func (service *OIDCService) ValidateGrantType(grantType string) error {
	if !slices.Contains(SupportedGrantTypes, grantType) {
		return errors.New("unsupported_grant_type")
	}

	return nil
}

func (service *OIDCService) GetCodeEntry(c *gin.Context, codeHash string, clientId string) (repository.OidcCode, error) {
	oidcCode, err := service.queries.GetOidcCode(c, codeHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.OidcCode{}, ErrCodeNotFound
		}
		return repository.OidcCode{}, err
	}

	if time.Now().Unix() > oidcCode.ExpiresAt {
		err = service.queries.DeleteOidcCode(c, codeHash)
		if err != nil {
			return repository.OidcCode{}, err
		}
		err = service.DeleteUserinfo(c, oidcCode.Sub)
		if err != nil {
			return repository.OidcCode{}, err
		}
		return repository.OidcCode{}, ErrCodeExpired
	}

	if oidcCode.ClientID != clientId {
		return repository.OidcCode{}, ErrInvalidClient
	}

	return oidcCode, nil
}

func (service *OIDCService) generateIDToken(client model.OIDCClientConfig, user repository.OidcUserinfo, scope string, nonce string) (string, error) {
	createdAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Duration(service.config.Auth.SessionExpiry) * time.Second).Unix()

	hasher := sha256.New()

	der := x509.MarshalPKCS1PublicKey(&service.privateKey.PublicKey)

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

func (service *OIDCService) GenerateAccessToken(c *gin.Context, client model.OIDCClientConfig, codeEntry repository.OidcCode) (TokenResponse, error) {
	user, err := service.GetUserinfo(c, codeEntry.Sub)

	if err != nil {
		return TokenResponse{}, err
	}

	idToken, err := service.generateIDToken(client, user, codeEntry.Scope, codeEntry.Nonce)

	if err != nil {
		return TokenResponse{}, err
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

	_, err = service.queries.CreateOidcToken(c, repository.CreateOidcTokenParams{
		Sub:                   codeEntry.Sub,
		AccessTokenHash:       service.Hash(accessToken),
		RefreshTokenHash:      service.Hash(refreshToken),
		ClientID:              client.ClientID,
		Scope:                 codeEntry.Scope,
		TokenExpiresAt:        tokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		Nonce:                 codeEntry.Nonce,
		CodeHash:              codeEntry.CodeHash,
	})

	if err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}

func (service *OIDCService) RefreshAccessToken(c *gin.Context, refreshToken string, reqClientId string) (TokenResponse, error) {
	entry, err := service.queries.GetOidcTokenByRefreshToken(c, service.Hash(refreshToken))

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenResponse{}, ErrTokenNotFound
		}
		return TokenResponse{}, err
	}

	if entry.RefreshTokenExpiresAt < time.Now().Unix() {
		return TokenResponse{}, ErrTokenExpired
	}

	// Ensure the client ID in the request matches the client ID in the token
	if entry.ClientID != reqClientId {
		return TokenResponse{}, ErrInvalidClient
	}

	user, err := service.GetUserinfo(c, entry.Sub)

	if err != nil {
		return TokenResponse{}, err
	}

	idToken, err := service.generateIDToken(model.OIDCClientConfig{
		ClientID: entry.ClientID,
	}, user, entry.Scope, entry.Nonce)

	if err != nil {
		return TokenResponse{}, err
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

	_, err = service.queries.UpdateOidcTokenByRefreshToken(c, repository.UpdateOidcTokenByRefreshTokenParams{
		AccessTokenHash:       service.Hash(accessToken),
		RefreshTokenHash:      service.Hash(newRefreshToken),
		TokenExpiresAt:        tokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		RefreshTokenHash_2:    service.Hash(refreshToken), // that's the selector, it's not stored in the db
	})

	if err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}

func (service *OIDCService) DeleteCodeEntry(c *gin.Context, codeHash string) error {
	return service.queries.DeleteOidcCode(c, codeHash)
}

func (service *OIDCService) DeleteUserinfo(c *gin.Context, sub string) error {
	return service.queries.DeleteOidcUserInfo(c, sub)
}

func (service *OIDCService) DeleteToken(c *gin.Context, tokenHash string) error {
	return service.queries.DeleteOidcToken(c, tokenHash)
}

func (service *OIDCService) DeleteTokenByCodeHash(c *gin.Context, codeHash string) error {
	return service.queries.DeleteOidcTokenByCodeHash(c, codeHash)
}

func (service *OIDCService) GetAccessToken(c *gin.Context, tokenHash string) (repository.OidcToken, error) {
	entry, err := service.queries.GetOidcToken(c, tokenHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.OidcToken{}, ErrTokenNotFound
		}
		return repository.OidcToken{}, err
	}

	if entry.TokenExpiresAt < time.Now().Unix() {
		// If refresh token is expired, delete the token and userinfo since there is no way for the client to access anything anymore
		if entry.RefreshTokenExpiresAt < time.Now().Unix() {
			err := service.DeleteToken(c, tokenHash)
			if err != nil {
				return repository.OidcToken{}, err
			}
			err = service.DeleteUserinfo(c, entry.Sub)
			if err != nil {
				return repository.OidcToken{}, err
			}
		}
		return repository.OidcToken{}, ErrTokenExpired
	}

	return entry, nil
}

func (service *OIDCService) GetUserinfo(c *gin.Context, sub string) (repository.OidcUserinfo, error) {
	return service.queries.GetOidcUserInfo(c, sub)
}

func (service *OIDCService) CompileUserinfo(user repository.OidcUserinfo, scope string) UserinfoResponse {
	scopes := strings.Split(scope, ",") // split by comma since it's a db entry
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
		if user.Groups != "" {
			userInfo.Groups = strings.Split(user.Groups, ",")
		} else {
			userInfo.Groups = []string{}
		}
	}

	if slices.Contains(scopes, "phone") {
		userInfo.PhoneNumber = user.PhoneNumber
		verified := user.PhoneNumber != ""
		userInfo.PhoneNumberVerified = &verified
	}

	if slices.Contains(scopes, "address") {
		var addr model.AddressClaim
		if err := json.Unmarshal([]byte(user.Address), &addr); err == nil {
			userInfo.Address = &addr
		}
	}

	return userInfo
}

func (service *OIDCService) Hash(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (service *OIDCService) DeleteOldSession(ctx context.Context, sub string) error {
	err := service.queries.DeleteOidcCodeBySub(ctx, sub)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	err = service.queries.DeleteOidcTokenBySub(ctx, sub)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	err = service.queries.DeleteOidcUserInfo(ctx, sub)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// Cleanup routine - Resource heavy due to the linked tables
func (service *OIDCService) cleanupRoutine() {
	service.log.App.Debug().Msg("Starting OIDC cleanup routine")
	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			service.log.App.Debug().Msg("Performing OIDC cleanup routine")

			currentTime := time.Now().Unix()

			// For the OIDC tokens, if they are expired we delete the userinfo and codes
			expiredTokens, err := service.queries.DeleteExpiredOidcTokens(service.context, repository.DeleteExpiredOidcTokensParams{
				TokenExpiresAt:        currentTime,
				RefreshTokenExpiresAt: currentTime,
			})

			if err != nil {
				service.log.App.Warn().Err(err).Msg("Failed to delete expired tokens")
			}

			for _, expiredToken := range expiredTokens {
				err := service.DeleteOldSession(service.context, expiredToken.Sub)
				if err != nil {
					service.log.App.Warn().Err(err).Msg("Failed to delete session for expired token")
				}
			}

			// For expired codes, we need to get the sub, check if tokens are expired and if they are remove everything
			expiredCodes, err := service.queries.DeleteExpiredOidcCodes(service.context, currentTime)

			if err != nil {
				service.log.App.Warn().Err(err).Msg("Failed to delete expired codes")
			}

			for _, expiredCode := range expiredCodes {
				token, err := service.queries.GetOidcTokenBySub(service.context, expiredCode.Sub)

				if err != nil {
					service.log.App.Warn().Err(err).Msg("Failed to get token by sub for expired code")
					continue
				}

				if token.TokenExpiresAt < currentTime && token.RefreshTokenExpiresAt < currentTime {
					err := service.DeleteOldSession(service.context, expiredCode.Sub)
					if err != nil {
						service.log.App.Warn().Err(err).Msg("Failed to delete session for expired code")
					}
				}
			}

			service.log.App.Debug().Msg("Finished OIDC cleanup routine")
		case <-service.context.Done():
			service.log.App.Debug().Msg("Stopping OIDC cleanup routine")
			return
		}
	}
}

func (service *OIDCService) GetJWK() ([]byte, error) {
	hasher := sha256.New()

	der := x509.MarshalPKCS1PublicKey(&service.privateKey.PublicKey)

	if der == nil {
		return nil, errors.New("failed to marshal public key")
	}

	hasher.Write(der)

	jwk := jose.JSONWebKey{
		Key:       service.privateKey,
		Algorithm: string(jose.RS256),
		Use:       "sig",
		KeyID:     base64.URLEncoding.EncodeToString(hasher.Sum(nil)),
	}

	return jwk.Public().MarshalJSON()
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
